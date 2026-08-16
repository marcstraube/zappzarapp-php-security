<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive
 * @noinspection PhpComposerExtensionStubsInspection psr/http-server-handler is optional (suggest)
 */

declare(strict_types=1);

namespace Zappzarapp\Security\Middleware;

use Closure;
use Override;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Random\RandomException;
use RuntimeException;
use Zappzarapp\Security\Csp\Exception\CspReportException;
use Zappzarapp\Security\Csp\Report\CspReportParser;
use Zappzarapp\Security\Logging\SecurityEvent;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;
use Zappzarapp\Security\RateLimiting\RateLimiter;
use Zappzarapp\Security\RateLimiting\RateLimitIdentifier;

/**
 * PSR-15 request handler for a CSP violation report endpoint
 *
 * Drop-in receiver for the URI configured via `report-uri` or the endpoint
 * behind a `report-to` group. It parses both wire formats, logs each
 * violation as a security event and answers every request with `204 No
 * Content`.
 *
 * ## Usage
 *
 * ```php
 * $handler = CspReportHandler::create(
 *     new SecurityAuditLogger($psrLogger),
 *     $responseFactory,
 *     new DefaultRateLimiter(new RateLimitConfig(limit: 60, window: 60)),
 * );
 *
 * // Route POST /csp-violations to $handler
 * $response = $handler->handle($request);
 * ```
 *
 * ## Why every report gets the same 204
 *
 * A report endpoint is unauthenticated by construction - the browser posts
 * to it before any session exists. Distinguishing responses would turn it
 * into an oracle: a sender could learn whether its payload parsed, how
 * large the accepted body is, or whether it is being rate limited, and use
 * that to tune a flood. Browsers ignore the response body either way, so
 * there is nothing to gain from a richer answer. Rejections are visible
 * where they belong - in the security log.
 *
 * Nothing about the request changes that: a malformed, oversized, wrongly
 * typed, unreadable or rate limited report is answered exactly like a
 * valid one, and a non-POST request never reaches the parser at all.
 *
 * A failure of the surrounding infrastructure is the deliberate exception.
 * If the rate limiter's storage or the logger throws, that exception
 * propagates and the request fails - swallowing it would leave the
 * endpoint accepting and logging without the limit it promises, which is
 * exactly the state it must not silently run in.
 *
 * ## Flood protection
 *
 * Anyone can POST to this endpoint, and a genuine misconfigured policy can
 * produce a report per blocked subresource per page view. Rate limiting is
 * therefore part of the constructor contract rather than an option:
 * {@see self::create()} requires a limiter, and giving it up takes the
 * explicitly named {@see self::withoutRateLimiting()}.
 *
 * The limiter is consulted before the body is parsed or logged, so a flood
 * costs neither parsing nor log volume.
 *
 * @see CspReportParser For the accepted payload formats and their limits
 */
final readonly class CspReportHandler implements RequestHandlerInterface
{
    /**
     * The only method a reporting endpoint accepts
     */
    private const string METHOD_POST = 'POST';

    /**
     * The single status code this handler ever returns
     */
    private const int STATUS_NO_CONTENT = 204;

    /**
     * Fallback identifier for requests without a remote address
     */
    private const string UNKNOWN_CLIENT = 'unknown';

    /** @var Closure(ServerRequestInterface): (RateLimitIdentifier|string) */
    private Closure $identifierExtractor;

    /**
     * @param RateLimiter|null $rateLimiter Flood protection, null only via withoutRateLimiting()
     * @param (callable(ServerRequestInterface): (RateLimitIdentifier|string))|null $identifierExtractor Custom identifier extractor, defaults to IP-based
     */
    private function __construct(
        private SecurityLoggerInterface $logger,
        private ResponseFactoryInterface $responseFactory,
        private ?RateLimiter $rateLimiter,
        private CspReportParser $parser,
        ?callable $identifierExtractor,
    ) {
        $this->identifierExtractor = $identifierExtractor !== null
            ? $identifierExtractor(...)
            : static function (ServerRequestInterface $request): RateLimitIdentifier {
                $remoteAddress = $request->getServerParams()['REMOTE_ADDR'] ?? null;

                return RateLimitIdentifier::fromIp(
                    is_string($remoteAddress) && $remoteAddress !== ''
                        ? $remoteAddress
                        : self::UNKNOWN_CLIENT
                );
            };
    }

    /**
     * Create a report endpoint with flood protection
     *
     * @param SecurityLoggerInterface $logger Receives the parsed violations and every rejection
     * @param ResponseFactoryInterface $responseFactory PSR-17 factory for the 204 response
     * @param RateLimiter $rateLimiter Consulted before parsing, per client identifier
     * @param CspReportParser|null $parser Custom parser, defaults to the standard limits
     * @param (callable(ServerRequestInterface): (RateLimitIdentifier|string))|null $identifierExtractor Custom identifier extractor, defaults to IP-based
     */
    public static function create(
        SecurityLoggerInterface $logger,
        ResponseFactoryInterface $responseFactory,
        RateLimiter $rateLimiter,
        ?CspReportParser $parser = null,
        ?callable $identifierExtractor = null,
    ): self {
        return new self(
            $logger,
            $responseFactory,
            $rateLimiter,
            $parser ?? new CspReportParser(),
            $identifierExtractor,
        );
    }

    /**
     * Create a report endpoint WITHOUT flood protection
     *
     * Only safe when something in front of the endpoint already bounds the
     * request rate - an API gateway, a reverse proxy or a
     * {@see RateLimitMiddleware} wrapping this handler. Without any of
     * those, a single sender can fill the security log at line speed.
     *
     * @param SecurityLoggerInterface $logger Receives the parsed violations and every rejection
     * @param ResponseFactoryInterface $responseFactory PSR-17 factory for the 204 response
     * @param CspReportParser|null $parser Custom parser, defaults to the standard limits
     */
    public static function withoutRateLimiting(
        SecurityLoggerInterface $logger,
        ResponseFactoryInterface $responseFactory,
        ?CspReportParser $parser = null,
    ): self {
        return new self(
            $logger,
            $responseFactory,
            null,
            $parser ?? new CspReportParser(),
            null,
        );
    }

    /**
     * Receive a violation report and answer 204 No Content
     *
     * @throws RandomException If correlation ID generation for a security event fails
     */
    #[Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->receive($request);

        return $this->responseFactory->createResponse(self::STATUS_NO_CONTENT);
    }

    /**
     * Parse and log the report, swallowing every rejection
     *
     * @throws RandomException If correlation ID generation for a security event fails
     */
    private function receive(ServerRequestInterface $request): void
    {
        if ($request->getMethod() !== self::METHOD_POST) {
            return;
        }

        if (!$this->passesFloodProtection($request)) {
            return;
        }

        try {
            $reports = $this->parser->parse(
                $this->readBody($request),
                $request->getHeaderLine('Content-Type'),
            );
        } catch (CspReportException $cspReportException) {
            $this->logger->securityEvent(SecurityEvent::cspReportRejected($cspReportException->getMessage()));

            return;
        }

        foreach ($reports as $report) {
            $this->logger->securityEvent(SecurityEvent::cspViolation($report->toLogContext()));
        }
    }

    /**
     * Whether the request may be parsed, consuming rate limit quota
     */
    private function passesFloodProtection(ServerRequestInterface $request): bool
    {
        if (!$this->rateLimiter instanceof RateLimiter) {
            return true;
        }

        $identifier = ($this->identifierExtractor)($request);

        return !$this->rateLimiter->consume($identifier)->isDenied();
    }

    /**
     * Read the request body, turning stream failures into a rejection
     *
     * PSR-7 streams may throw while being read - a connection dropped
     * mid-body is the common case. That must not escape as a 500: this
     * endpoint answers 204 to everything, so an unreadable body is just
     * another report that could not be accepted.
     *
     * @throws CspReportException If the body cannot be read to the end
     */
    private function readBody(ServerRequestInterface $request): string
    {
        try {
            return $this->readChunks($request);
        } catch (RuntimeException) {
            throw CspReportException::unreadableBody();
        }
    }

    /**
     * Read the stream without buffering an unbounded amount of it
     *
     * Reading continues one chunk past the limit rather than stopping at
     * it: that surplus is what tells an oversized body apart from one that
     * exactly fills the limit, and the parser turns it into a rejection.
     * A body that never ends therefore costs twice the limit rather than
     * the whole stream.
     *
     * @throws RuntimeException If the stream cannot be rewound or read
     */
    private function readChunks(ServerRequestInterface $request): string
    {
        $body = $request->getBody();

        if ($body->isSeekable()) {
            $body->rewind();
        }

        $limit   = $this->parser->maxPayloadBytes;
        $payload = '';

        while (strlen($payload) <= $limit) {
            $chunk = $body->read($limit);

            if ($chunk === '') {
                break;
            }

            $payload .= $chunk;
        }

        return $payload;
    }
}
