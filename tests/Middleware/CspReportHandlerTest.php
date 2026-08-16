<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */
/** @noinspection PhpDocMissingThrowsInspection Same convention: a @param docblock does not oblige a test method to document @throws */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Middleware;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Zappzarapp\Security\Csp\Report\CspReportParser;
use Zappzarapp\Security\Logging\SecurityEvent;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;
use Zappzarapp\Security\Middleware\CspReportHandler;
use Zappzarapp\Security\RateLimiting\RateLimiter;
use Zappzarapp\Security\RateLimiting\RateLimitIdentifier;
use Zappzarapp\Security\RateLimiting\RateLimitResult;

#[CoversClass(CspReportHandler::class)]
#[UsesClass(CspReportParser::class)]
#[UsesClass(SecurityEvent::class)]
#[UsesClass(RateLimitIdentifier::class)]
#[UsesClass(RateLimitResult::class)]
final class CspReportHandlerTest extends TestCase
{
    /** @var list<SecurityEvent> */
    private array $events = [];

    /** @var list<string> */
    private array $consumed = [];

    protected function setUp(): void
    {
        $this->events   = [];
        $this->consumed = [];
    }

    // ---------------------------------------------------------------
    // Response
    // ---------------------------------------------------------------

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function everyRequestShapeProvider(): iterable
    {
        yield 'valid report' => ['POST', self::legacyPayload()];
        yield 'malformed body' => ['POST', 'not json'];
        yield 'empty body' => ['POST', ''];
        yield 'wrong method' => ['GET', self::legacyPayload()];
    }

    #[DataProvider('everyRequestShapeProvider')]
    #[Test]
    public function testAlwaysAnswersWith204(string $method, string $body): void
    {
        $response = $this->createHandler()->handle($this->createRequest($body, method: $method));

        $this->assertSame(204, $response->getStatusCode());
    }

    // ---------------------------------------------------------------
    // Logging
    // ---------------------------------------------------------------

    #[Test]
    public function testLogsAViolationForAValidLegacyReport(): void
    {
        $this->createHandler()->handle($this->createRequest(self::legacyPayload()));

        $this->assertCount(1, $this->events);
        $this->assertSame('security.csp.violation_reported', $this->events[0]->type->value);
        $this->assertSame('https://example.com/signup', $this->events[0]->context['document_uri']);
        $this->assertSame('script-src', $this->events[0]->context['effective_directive']);
        $this->assertSame('https://evil.example.com/payload.js', $this->events[0]->context['blocked_uri']);
    }

    #[Test]
    public function testLogsAViolationPerReportInABatch(): void
    {
        $payload = json_encode([
            ['type' => 'csp-violation', 'body' => ['documentURL' => 'https://example.com/a', 'effectiveDirective' => 'img-src']],
            ['type' => 'csp-violation', 'body' => ['documentURL' => 'https://example.com/b', 'effectiveDirective' => 'font-src']],
        ], JSON_THROW_ON_ERROR);

        $request = $this->createRequest($payload, CspReportParser::CONTENT_TYPE_REPORTING_API);

        $this->createHandler()->handle($request);

        $this->assertCount(2, $this->events);
        $this->assertSame('https://example.com/a', $this->events[0]->context['document_uri']);
        $this->assertSame('https://example.com/b', $this->events[1]->context['document_uri']);
    }

    #[Test]
    public function testLogsNothingForABatchWithoutCspViolations(): void
    {
        $payload = json_encode([
            ['type' => 'deprecation', 'body' => ['id' => 'PrefixedStorageInfo']],
        ], JSON_THROW_ON_ERROR);

        $this->createHandler()->handle($this->createRequest($payload, CspReportParser::CONTENT_TYPE_REPORTING_API));

        $this->assertSame([], $this->events);
    }

    #[Test]
    public function testLogsARejectionForAMalformedPayload(): void
    {
        $this->createHandler()->handle($this->createRequest('not json'));

        $this->assertCount(1, $this->events);
        $this->assertSame('security.csp.report_rejected', $this->events[0]->type->value);
        $this->assertSame('CSP report body is not valid JSON', $this->events[0]->context['reason']);
    }

    #[Test]
    public function testTheRejectionReasonNeverCarriesPayloadContent(): void
    {
        $payload = json_encode(['csp-report' => 'attacker-controlled-marker'], JSON_THROW_ON_ERROR);

        $this->createHandler()->handle($this->createRequest($payload));

        $this->assertCount(1, $this->events);
        $this->assertStringNotContainsString(
            'attacker-controlled-marker',
            (string) $this->events[0]->context['reason']
        );
    }

    #[Test]
    public function testIgnoresANonPostRequestWithoutReadingTheBody(): void
    {
        $body = $this->createMock(StreamInterface::class);
        $body->expects($this->never())->method('read');

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('GET');
        $request->method('getBody')->willReturn($body);

        $this->createHandler()->handle($request);

        $this->assertSame([], $this->events);
    }

    // ---------------------------------------------------------------
    // Flood protection
    // ---------------------------------------------------------------

    #[Test]
    public function testDoesNotParseAReportOnceRateLimited(): void
    {
        $limiter = $this->createStub(RateLimiter::class);
        $limiter->method('consume')->willReturn(RateLimitResult::denied(10, time() + 60, 60));

        $handler = CspReportHandler::create($this->createLogger(), $this->createResponseFactory(), $limiter);

        $response = $handler->handle($this->createRequest(self::legacyPayload()));

        $this->assertSame([], $this->events, 'A rate limited report must not reach the log');
        $this->assertSame(204, $response->getStatusCode());
    }

    #[Test]
    public function testConsumesQuotaPerRequestAndStopsAtTheLimit(): void
    {
        $remaining = 2;

        $limiter = $this->createStub(RateLimiter::class);
        $limiter->method('consume')->willReturnCallback(
            static function () use (&$remaining): RateLimitResult {
                if ($remaining < 1) {
                    return RateLimitResult::denied(2, time() + 60, 60);
                }

                --$remaining;

                return RateLimitResult::allowed(2, $remaining, time() + 60);
            }
        );

        $handler = CspReportHandler::create($this->createLogger(), $this->createResponseFactory(), $limiter);

        for ($sent = 0; $sent < 5; ++$sent) {
            $handler->handle($this->createRequest(self::legacyPayload()));
        }

        $this->assertCount(2, $this->events);
    }

    #[Test]
    public function testRateLimitsPerClientAddress(): void
    {
        $handler = CspReportHandler::create(
            $this->createLogger(),
            $this->createResponseFactory(),
            $this->createRecordingLimiter(),
        );

        $handler->handle($this->createRequest(self::legacyPayload(), serverParams: ['REMOTE_ADDR' => '203.0.113.7']));

        $this->assertSame(['ip:203.0.113.7'], $this->consumed);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function unusableRemoteAddressProvider(): iterable
    {
        yield 'missing' => [[]];
        yield 'empty' => [['REMOTE_ADDR' => '']];
        yield 'not a string' => [['REMOTE_ADDR' => 42]];
    }

    /**
     * @param array<string, mixed> $serverParams
     */
    #[DataProvider('unusableRemoteAddressProvider')]
    #[Test]
    public function testFallsBackToAnUnknownClientIdentifier(array $serverParams): void
    {
        $handler = CspReportHandler::create(
            $this->createLogger(),
            $this->createResponseFactory(),
            $this->createRecordingLimiter(),
        );

        $handler->handle($this->createRequest(self::legacyPayload(), serverParams: $serverParams));

        $this->assertSame(['ip:unknown'], $this->consumed);
    }

    #[Test]
    public function testUsesACustomIdentifierExtractor(): void
    {
        $handler = CspReportHandler::create(
            $this->createLogger(),
            $this->createResponseFactory(),
            $this->createRecordingLimiter(),
            identifierExtractor: static fn (ServerRequestInterface $request): RateLimitIdentifier
                => RateLimitIdentifier::custom('csp', $request->getHeaderLine('X-Site')),
        );

        $handler->handle($this->createRequest(self::legacyPayload(), headers: ['X-Site' => 'shop']));

        $this->assertSame(['csp:shop'], $this->consumed);
    }

    #[Test]
    public function testWithoutRateLimitingAcceptsEveryReport(): void
    {
        $handler = CspReportHandler::withoutRateLimiting($this->createLogger(), $this->createResponseFactory());

        for ($sent = 0; $sent < 5; ++$sent) {
            $handler->handle($this->createRequest(self::legacyPayload()));
        }

        $this->assertCount(5, $this->events);
    }

    // ---------------------------------------------------------------
    // Body reading
    // ---------------------------------------------------------------

    #[Test]
    public function testRewindsASeekableBody(): void
    {
        $body = $this->createMock(StreamInterface::class);
        $body->method('isSeekable')->willReturn(true);
        $body->method('read')->willReturnCallback($this->bodyReader(self::legacyPayload(), null));
        $body->expects($this->once())->method('rewind');

        $this->createHandler()->handle($this->createRequestWithBody($body));

        $this->assertCount(1, $this->events);
    }

    #[Test]
    public function testDoesNotRewindANonSeekableBody(): void
    {
        $body = $this->createMock(StreamInterface::class);
        $body->method('isSeekable')->willReturn(false);
        $body->method('read')->willReturnCallback($this->bodyReader(self::legacyPayload(), null));
        $body->expects($this->never())->method('rewind');

        $this->createHandler()->handle($this->createRequestWithBody($body));

        $this->assertCount(1, $this->events);
    }

    #[Test]
    public function testAssemblesABodyThatArrivesInSmallChunks(): void
    {
        $body = $this->createBodyStub(self::minimalPayload(), chunkSize: 7);

        $this->createHandler()->handle($this->createRequestWithBody($body));

        $this->assertCount(1, $this->events);
        $this->assertSame('security.csp.violation_reported', $this->events[0]->type->value);
    }

    #[Test]
    public function testAcceptsABodyThatExactlyFillsTheLimit(): void
    {
        $payload = self::minimalPayload();
        $handler = $this->createHandler(new CspReportParser(strlen($payload)));

        $handler->handle($this->createRequestWithBody($this->createBodyStub($payload)));

        $this->assertCount(1, $this->events);
        $this->assertSame('security.csp.violation_reported', $this->events[0]->type->value);
    }

    #[Test]
    public function testRejectsABodyOneByteBeyondTheLimit(): void
    {
        $payload = self::minimalPayload();
        $handler = $this->createHandler(new CspReportParser(strlen($payload) - 1));

        $handler->handle($this->createRequestWithBody($this->createBodyStub($payload)));

        $this->assertCount(1, $this->events);
        $this->assertSame('security.csp.report_rejected', $this->events[0]->type->value);
        $this->assertStringContainsString('exceeds the maximum', (string) $this->events[0]->context['reason']);
    }

    #[Test]
    public function testAnswers204WhenTheBodyCannotBeRead(): void
    {
        $body = $this->createStub(StreamInterface::class);
        $body->method('isSeekable')->willReturn(false);
        $body->method('read')->willThrowException(new RuntimeException('connection reset by peer'));

        $response = $this->createHandler()->handle($this->createRequestWithBody($body));

        $this->assertSame(204, $response->getStatusCode());
        $this->assertCount(1, $this->events);
        $this->assertSame('security.csp.report_rejected', $this->events[0]->type->value);
        $this->assertSame('CSP report body could not be read', $this->events[0]->context['reason']);
    }

    #[Test]
    public function testTheRejectionReasonNeverCarriesTheStreamError(): void
    {
        $body = $this->createStub(StreamInterface::class);
        $body->method('isSeekable')->willReturn(false);
        $body->method('read')->willThrowException(new RuntimeException('/var/run/php/internal-detail.sock'));

        $this->createHandler()->handle($this->createRequestWithBody($body));

        $this->assertStringNotContainsString(
            'internal-detail',
            (string) $this->events[0]->context['reason']
        );
    }

    #[Test]
    public function testStopsReadingAtTheEndOfTheStream(): void
    {
        $this->createHandler()->handle($this->createRequestWithBody($this->createBodyStub('')));

        $this->assertCount(1, $this->events);
        $this->assertSame('security.csp.report_rejected', $this->events[0]->type->value);
    }

    #[Test]
    public function testUsesTheParserPassedIn(): void
    {
        $handler = CspReportHandler::withoutRateLimiting(
            $this->createLogger(),
            $this->createResponseFactory(),
            new CspReportParser(4),
        );

        $handler->handle($this->createRequest(self::legacyPayload()));

        $this->assertCount(1, $this->events);
        $this->assertSame('CSP report payload exceeds the maximum of 4 bytes', $this->events[0]->context['reason']);
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private function createHandler(?CspReportParser $parser = null): CspReportHandler
    {
        $limiter = $this->createStub(RateLimiter::class);
        $limiter->method('consume')->willReturn(RateLimitResult::allowed(100, 99, time() + 60));

        return CspReportHandler::create(
            $this->createLogger(),
            $this->createResponseFactory(),
            $limiter,
            $parser,
        );
    }

    /**
     * Record which identifier each request is charged against
     */
    private function createRecordingLimiter(): RateLimiter
    {
        $limiter = $this->createStub(RateLimiter::class);
        $limiter->method('consume')->willReturnCallback(
            function (RateLimitIdentifier|string $identifier): RateLimitResult {
                $this->consumed[] = $identifier instanceof RateLimitIdentifier
                    ? $identifier->value()
                    : $identifier;

                return RateLimitResult::allowed(10, 9, time() + 60);
            }
        );

        return $limiter;
    }

    private function createLogger(): SecurityLoggerInterface
    {
        $logger = $this->createStub(SecurityLoggerInterface::class);
        $logger->method('securityEvent')->willReturnCallback(
            function (SecurityEvent $event): void {
                $this->events[] = $event;
            }
        );

        return $logger;
    }

    private function createResponseFactory(): ResponseFactoryInterface
    {
        $factory = $this->createStub(ResponseFactoryInterface::class);
        $factory->method('createResponse')->willReturnCallback(
            function (int $code): ResponseInterface {
                $response = $this->createStub(ResponseInterface::class);
                $response->method('getStatusCode')->willReturn($code);

                return $response;
            }
        );

        return $factory;
    }

    /**
     * Build a reader that honours the requested length, so the handler's
     * chunked reading is exercised for real
     *
     * @param int|null $chunkSize Cap on bytes returned per call, null to serve the full request
     *
     * @return callable(int): string
     */
    private function bodyReader(string $content, ?int $chunkSize): callable
    {
        $offset = 0;

        return static function (int $length) use ($content, $chunkSize, &$offset): string {
            $chunk   = substr($content, $offset, min($length, $chunkSize ?? $length));
            $offset += strlen($chunk);

            return $chunk;
        };
    }

    private function createBodyStub(string $content, ?int $chunkSize = null): StreamInterface
    {
        $body = $this->createStub(StreamInterface::class);
        $body->method('isSeekable')->willReturn(true);
        $body->method('read')->willReturnCallback($this->bodyReader($content, $chunkSize));

        return $body;
    }

    /**
     * @param array<string, string> $headers
     * @param array<string, mixed> $serverParams
     */
    private function createRequest(
        string $body,
        string $contentType = CspReportParser::CONTENT_TYPE_LEGACY,
        string $method = 'POST',
        array $headers = [],
        array $serverParams = ['REMOTE_ADDR' => '127.0.0.1'],
    ): ServerRequestInterface {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn($method);
        $request->method('getBody')->willReturn($this->createBodyStub($body));
        $request->method('getServerParams')->willReturn($serverParams);
        $request->method('getHeaderLine')->willReturnCallback(
            static fn (string $name): string => $name === 'Content-Type'
                ? $contentType
                : ($headers[$name] ?? '')
        );

        return $request;
    }

    private function createRequestWithBody(StreamInterface $body): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getBody')->willReturn($body);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => '127.0.0.1']);
        $request->method('getHeaderLine')->willReturn(CspReportParser::CONTENT_TYPE_LEGACY);

        return $request;
    }

    private static function legacyPayload(): string
    {
        return '{"csp-report":{"document-uri":"https://example.com/signup",'
            . '"violated-directive":"script-src",'
            . '"blocked-uri":"https://evil.example.com/payload.js"}}';
    }

    private static function minimalPayload(): string
    {
        return '{"csp-report":{"document-uri":"https://example.com/","violated-directive":"script-src"}}';
    }
}
