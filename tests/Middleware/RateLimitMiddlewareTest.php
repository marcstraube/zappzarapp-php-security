<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Middleware;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zappzarapp\Security\Middleware\RateLimitMiddleware;
use Zappzarapp\Security\RateLimiting\DefaultRateLimiter;
use Zappzarapp\Security\RateLimiting\RateLimitConfig;
use Zappzarapp\Security\RateLimiting\RateLimiter;
use Zappzarapp\Security\RateLimiting\RateLimitIdentifier;
use Zappzarapp\Security\RateLimiting\RateLimitResult;
use Zappzarapp\Security\RateLimiting\Storage\InMemoryStorage;

#[CoversClass(RateLimitMiddleware::class)]
#[UsesClass(DefaultRateLimiter::class)]
#[UsesClass(RateLimitConfig::class)]
#[UsesClass(RateLimitIdentifier::class)]
#[UsesClass(RateLimitResult::class)]
#[UsesClass(InMemoryStorage::class)]
final class RateLimitMiddlewareTest extends TestCase
{
    #[Test]
    public function testAllowedRequestPassesThrough(): void
    {
        $limiter    = new DefaultRateLimiter(new RateLimitConfig(limit: 10, window: 60));
        $middleware = new RateLimitMiddleware($limiter, $this->createResponseFactory());

        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturn($response);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        $request = $this->createRequest('127.0.0.1');

        $middleware->process($request, $handler);
    }

    #[Test]
    public function testDeniedRequestReturns429WithHeaders(): void
    {
        $result = RateLimitResult::denied(10, time() + 60, 60);

        $limiter = $this->createMock(RateLimiter::class);
        $limiter->method('consume')->willReturn($result);

        $appliedHeaders = [];

        $deniedResponse = $this->createMock(ResponseInterface::class);
        $deniedResponse->method('withHeader')
            ->willReturnCallback(function (string $name, string $value) use (&$appliedHeaders, $deniedResponse): ResponseInterface {
                $appliedHeaders[$name] = $value;

                return $deniedResponse;
            });

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects($this->once())
            ->method('createResponse')
            ->with(429)
            ->willReturn($deniedResponse);

        $middleware = new RateLimitMiddleware($limiter, $responseFactory);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $middleware->process($this->createRequest('127.0.0.1'), $handler);

        $this->assertArrayHasKey('Retry-After', $appliedHeaders);
        $this->assertArrayHasKey('X-RateLimit-Limit', $appliedHeaders);
    }

    #[Test]
    public function testAppliesRateLimitHeaders(): void
    {
        $limiter    = new DefaultRateLimiter(new RateLimitConfig(limit: 10, window: 60));
        $middleware = new RateLimitMiddleware($limiter, $this->createResponseFactory());

        $appliedHeaders = [];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('withHeader')
            ->willReturnCallback(function (string $name, string $value) use (&$appliedHeaders, $response): ResponseInterface {
                $appliedHeaders[$name] = $value;

                return $response;
            });

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $middleware->process($this->createRequest('127.0.0.1'), $handler);

        $this->assertArrayHasKey('X-RateLimit-Limit', $appliedHeaders);
        $this->assertArrayHasKey('X-RateLimit-Remaining', $appliedHeaders);
        $this->assertArrayHasKey('X-RateLimit-Reset', $appliedHeaders);
    }

    #[Test]
    public function testCustomIdentifierExtractor(): void
    {
        $result = RateLimitResult::allowed(10, 9, time() + 60);

        $limiter = $this->createMock(RateLimiter::class);
        $limiter->expects($this->once())
            ->method('consume')
            ->with('custom:api-key-123')
            ->willReturn($result);

        $extractor  = static fn (ServerRequestInterface $request): string => 'custom:api-key-123';
        $middleware = new RateLimitMiddleware($limiter, $this->createResponseFactory(), $extractor);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturn($response);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $middleware->process($this->createRequest('127.0.0.1'), $handler);
    }

    #[Test]
    public function testDefaultIdentifierUsesRemoteAddr(): void
    {
        $result = RateLimitResult::allowed(10, 9, time() + 60);

        $limiter = $this->createMock(RateLimiter::class);
        $limiter->expects($this->once())
            ->method('consume')
            ->with($this->callback(fn (mixed $id): bool => $id instanceof RateLimitIdentifier
                && str_contains($id->value(), '192.168.1.1')))
            ->willReturn($result);

        $middleware = new RateLimitMiddleware($limiter, $this->createResponseFactory());

        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturn($response);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $middleware->process($this->createRequest('192.168.1.1'), $handler);
    }

    private function createRequest(string $remoteAddr): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getServerParams')->willReturn(['REMOTE_ADDR' => $remoteAddr]);

        return $request;
    }

    private function createResponseFactory(): ResponseFactoryInterface
    {
        $factory = $this->createStub(ResponseFactoryInterface::class);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturn($response);

        $factory->method('createResponse')->willReturn($response);

        return $factory;
    }
}
