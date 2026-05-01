<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Middleware;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zappzarapp\Security\Headers\Builder\SecurityHeadersBuilder;
use Zappzarapp\Security\Headers\Hsts\HstsConfig;
use Zappzarapp\Security\Headers\SecurityHeaders;
use Zappzarapp\Security\Middleware\SecurityHeadersMiddleware;

#[CoversClass(SecurityHeadersMiddleware::class)]
#[UsesClass(SecurityHeadersBuilder::class)]
#[UsesClass(SecurityHeaders::class)]
#[UsesClass(HstsConfig::class)]
final class SecurityHeadersMiddlewareTest extends TestCase
{
    #[Test]
    public function testAppliesSecurityHeaders(): void
    {
        $headers    = SecurityHeaders::strict();
        $middleware = new SecurityHeadersMiddleware($headers);

        $appliedHeaders = [];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('withHeader')
            ->willReturnCallback(function (string $name, string $value) use (&$appliedHeaders, $response): ResponseInterface {
                $appliedHeaders[$name] = $value;

                return $response;
            });

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $request = $this->createStub(ServerRequestInterface::class);

        $middleware->process($request, $handler);

        $this->assertArrayHasKey('Strict-Transport-Security', $appliedHeaders);
        $this->assertArrayHasKey('X-Content-Type-Options', $appliedHeaders);
    }

    #[Test]
    public function testPassesRequestToHandler(): void
    {
        $headers    = SecurityHeaders::development();
        $middleware = new SecurityHeadersMiddleware($headers);

        $request  = $this->createStub(ServerRequestInterface::class);
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturn($response);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())
            ->method('handle')
            ->with($request)
            ->willReturn($response);

        $middleware->process($request, $handler);
    }

    #[Test]
    public function testDevelopmentHeadersApplyMinimalSet(): void
    {
        $headers    = SecurityHeaders::development();
        $middleware = new SecurityHeadersMiddleware($headers);

        $appliedHeaders = [];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('withHeader')
            ->willReturnCallback(function (string $name, string $value) use (&$appliedHeaders, $response): ResponseInterface {
                $appliedHeaders[$name] = $value;

                return $response;
            });

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $middleware->process($this->createStub(ServerRequestInterface::class), $handler);

        $this->assertArrayHasKey('X-Content-Type-Options', $appliedHeaders);
        $this->assertArrayNotHasKey('Strict-Transport-Security', $appliedHeaders);
    }
}
