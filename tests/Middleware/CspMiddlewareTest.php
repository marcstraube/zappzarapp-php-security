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
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\HeaderBuilder;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;
use Zappzarapp\Security\Csp\Nonce\NonceProvider;
use Zappzarapp\Security\Middleware\CspMiddleware;

#[CoversClass(CspMiddleware::class)]
#[UsesClass(CspDirectives::class)]
#[UsesClass(HeaderBuilder::class)]
#[UsesClass(NonceGenerator::class)]
final class CspMiddlewareTest extends TestCase
{
    #[Test]
    public function testAppliesCspHeader(): void
    {
        $directives = CspDirectives::strict();
        $middleware = new CspMiddleware($directives);

        $appliedHeaders = [];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('withHeader')
            ->willReturnCallback(function (string $name, string $value) use (&$appliedHeaders, $response): ResponseInterface {
                $appliedHeaders[$name] = $value;

                return $response;
            });

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('withAttribute')->willReturn($request);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $middleware->process($request, $handler);

        $this->assertArrayHasKey('Content-Security-Policy', $appliedHeaders);
        $this->assertStringContainsString("default-src 'self'", $appliedHeaders['Content-Security-Policy']);
    }

    #[Test]
    public function testReportOnlyMode(): void
    {
        $directives = CspDirectives::strict();
        $middleware = new CspMiddleware($directives, reportOnly: true);

        $appliedHeaders = [];

        $response = $this->createMock(ResponseInterface::class);
        $response->method('withHeader')
            ->willReturnCallback(function (string $name, string $value) use (&$appliedHeaders, $response): ResponseInterface {
                $appliedHeaders[$name] = $value;

                return $response;
            });

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('withAttribute')->willReturn($request);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $middleware->process($request, $handler);

        $this->assertArrayHasKey('Content-Security-Policy-Report-Only', $appliedHeaders);
        $this->assertArrayNotHasKey('Content-Security-Policy', $appliedHeaders);
    }

    #[Test]
    public function testStoresNonceProviderInRequestAttribute(): void
    {
        $nonce      = $this->createStub(NonceProvider::class);
        $directives = CspDirectives::strict();
        $middleware = new CspMiddleware($directives, $nonce);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturn($response);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())
            ->method('withAttribute')
            ->with(CspMiddleware::NONCE_ATTRIBUTE, $nonce)
            ->willReturn($request);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $middleware->process($request, $handler);
    }

    #[Test]
    public function testCreatesNonceGeneratorWhenNoneProvided(): void
    {
        $directives = CspDirectives::strict();
        $middleware = new CspMiddleware($directives);

        $storedProvider = null;

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('withAttribute')
            ->willReturnCallback(function (string $name, mixed $value) use (&$storedProvider, $request): ServerRequestInterface {
                if ($name === CspMiddleware::NONCE_ATTRIBUTE) {
                    $storedProvider = $value;
                }

                return $request;
            });

        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturn($response);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $middleware->process($request, $handler);

        $this->assertInstanceOf(NonceProvider::class, $storedProvider);
    }
}
