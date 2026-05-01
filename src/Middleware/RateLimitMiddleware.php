<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive
 * @noinspection PhpComposerExtensionStubsInspection psr/http-server-middleware is optional (suggest)
 */

declare(strict_types=1);

namespace Zappzarapp\Security\Middleware;

use Closure;
use Override;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zappzarapp\Security\RateLimiting\RateLimiter;
use Zappzarapp\Security\RateLimiting\RateLimitIdentifier;

/**
 * PSR-15 middleware for rate limiting
 *
 * Enforces rate limits and returns 429 responses with Retry-After headers
 * when the limit is exceeded. Rate limit headers are applied to all responses.
 */
final readonly class RateLimitMiddleware implements MiddlewareInterface
{
    /** @var Closure(ServerRequestInterface): (RateLimitIdentifier|string) */
    private Closure $identifierExtractor;

    /**
     * @param RateLimiter $limiter Rate limiter instance
     * @param ResponseFactoryInterface $responseFactory PSR-17 response factory for 429 responses
     * @param (callable(ServerRequestInterface): (RateLimitIdentifier|string))|null $identifierExtractor Custom identifier extractor, defaults to IP-based
     */
    public function __construct(
        private RateLimiter $limiter,
        private ResponseFactoryInterface $responseFactory,
        ?callable $identifierExtractor = null,
    ) {
        $this->identifierExtractor = $identifierExtractor !== null
            ? $identifierExtractor(...)
            : static fn (ServerRequestInterface $request): RateLimitIdentifier => RateLimitIdentifier::fromIp(
                (string) ($request->getServerParams()['REMOTE_ADDR'] ?? '127.0.0.1'),
            );
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $identifier = ($this->identifierExtractor)($request);
        $result     = $this->limiter->consume($identifier);

        if ($result->isDenied()) {
            $response = $this->responseFactory->createResponse(429);

            foreach ($result->toHeaders() as $name => $value) {
                $response = $response->withHeader($name, $value);
            }

            return $response;
        }

        $response = $handler->handle($request);

        foreach ($result->toHeaders() as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }
}
