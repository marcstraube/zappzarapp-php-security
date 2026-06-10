<?php

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
use Zappzarapp\Security\Cors\CorsConfig;
use Zappzarapp\Security\Middleware\CorsMiddleware;

#[CoversClass(CorsMiddleware::class)]
#[UsesClass(CorsConfig::class)]
final class CorsMiddlewareTest extends TestCase
{
    #[Test]
    public function testRequestWithoutOriginPassesThrough(): void
    {
        $headers    = [];
        $response   = $this->captureResponse($headers);
        $request    = $this->request(origin: '');
        $middleware = new CorsMiddleware(CorsConfig::permissive(), $this->unusedFactory());

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->with($request)->willReturn($response);

        self::assertSame($response, $middleware->process($request, $handler));
        self::assertSame([], $headers);
    }

    #[Test]
    public function testSimpleRequestAddsOriginAndVaryHeaders(): void
    {
        $headers    = [];
        $response   = $this->captureResponse($headers);
        $config     = new CorsConfig(allowedOrigins: ['https://example.com']);
        $middleware = new CorsMiddleware($config, $this->unusedFactory());

        $middleware->process(
            $this->request(origin: 'https://example.com'),
            $this->handlerReturning($response),
        );

        self::assertSame('https://example.com', $headers['Access-Control-Allow-Origin']);
        self::assertSame('Origin', $headers['Vary']);
        self::assertArrayNotHasKey('Access-Control-Allow-Credentials', $headers);
        self::assertArrayNotHasKey('Access-Control-Expose-Headers', $headers);
    }

    #[Test]
    public function testWildcardOriginOmitsVaryHeader(): void
    {
        $headers    = [];
        $response   = $this->captureResponse($headers);
        $middleware = new CorsMiddleware(CorsConfig::permissive(), $this->unusedFactory());

        $middleware->process(
            $this->request(origin: 'https://anything.test'),
            $this->handlerReturning($response),
        );

        self::assertSame('*', $headers['Access-Control-Allow-Origin']);
        self::assertArrayNotHasKey('Vary', $headers);
    }

    #[Test]
    public function testCredentialsHeaderIsAdded(): void
    {
        $headers    = [];
        $response   = $this->captureResponse($headers);
        $config     = new CorsConfig(allowedOrigins: ['https://example.com'], allowCredentials: true);
        $middleware = new CorsMiddleware($config, $this->unusedFactory());

        $middleware->process(
            $this->request(origin: 'https://example.com'),
            $this->handlerReturning($response),
        );

        self::assertSame('https://example.com', $headers['Access-Control-Allow-Origin']);
        self::assertSame('true', $headers['Access-Control-Allow-Credentials']);
        self::assertSame('Origin', $headers['Vary']);
    }

    #[Test]
    public function testExposedHeadersAreAdded(): void
    {
        $headers    = [];
        $response   = $this->captureResponse($headers);
        $config     = (new CorsConfig(allowedOrigins: ['https://example.com']))
            ->withExposedHeaders(['X-Total-Count', 'X-Page']);
        $middleware = new CorsMiddleware($config, $this->unusedFactory());

        $middleware->process(
            $this->request(origin: 'https://example.com'),
            $this->handlerReturning($response),
        );

        self::assertSame('X-Total-Count, X-Page', $headers['Access-Control-Expose-Headers']);
    }

    #[Test]
    public function testDisallowedOriginGetsNoCorsHeaders(): void
    {
        $headers    = [];
        $response   = $this->captureResponse($headers);
        $config     = new CorsConfig(allowedOrigins: ['https://example.com']);
        $middleware = new CorsMiddleware($config, $this->unusedFactory());

        $result = $middleware->process(
            $this->request(origin: 'https://evil.com'),
            $this->handlerReturning($response),
        );

        self::assertSame($response, $result);
        self::assertSame([], $headers);
    }

    #[Test]
    public function testPreflightReturns204WithCorsHeaders(): void
    {
        $headers  = [];
        $response = $this->captureResponse($headers);
        $config   = new CorsConfig(
            allowedOrigins: ['https://example.com'],
            allowedMethods: ['GET', 'POST'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            maxAge: 3600,
        );

        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects($this->once())->method('createResponse')->with(204)->willReturn($response);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $middleware = new CorsMiddleware($config, $factory);
        $result     = $middleware->process(
            $this->request(origin: 'https://example.com', method: 'OPTIONS', hasRequestMethod: true),
            $handler,
        );

        self::assertSame($response, $result);
        self::assertSame('https://example.com', $headers['Access-Control-Allow-Origin']);
        self::assertSame('GET, POST', $headers['Access-Control-Allow-Methods']);
        self::assertSame('Content-Type, Authorization', $headers['Access-Control-Allow-Headers']);
        self::assertSame('3600', $headers['Access-Control-Max-Age']);
        self::assertSame('Origin', $headers['Vary']);
    }

    #[Test]
    public function testPreflightOmitsOptionalHeadersWhenUnset(): void
    {
        $headers  = [];
        $response = $this->captureResponse($headers);
        $config   = new CorsConfig(allowedOrigins: ['https://example.com'], allowedMethods: [], allowedHeaders: []);

        $factory = $this->createStub(ResponseFactoryInterface::class);
        $factory->method('createResponse')->willReturn($response);

        $middleware = new CorsMiddleware($config, $factory);
        $middleware->process(
            $this->request(origin: 'https://example.com', method: 'OPTIONS', hasRequestMethod: true),
            $this->neverCalledHandler(),
        );

        self::assertArrayHasKey('Access-Control-Allow-Origin', $headers);
        self::assertArrayNotHasKey('Access-Control-Allow-Methods', $headers);
        self::assertArrayNotHasKey('Access-Control-Allow-Headers', $headers);
        self::assertArrayNotHasKey('Access-Control-Max-Age', $headers);
    }

    #[Test]
    public function testPreflightWithDisallowedOriginReturns204WithoutCorsHeaders(): void
    {
        $headers  = [];
        $response = $this->captureResponse($headers);
        $config   = new CorsConfig(allowedOrigins: ['https://example.com']);

        $factory = $this->createMock(ResponseFactoryInterface::class);
        $factory->expects($this->once())->method('createResponse')->with(204)->willReturn($response);

        $middleware = new CorsMiddleware($config, $factory);
        $result     = $middleware->process(
            $this->request(origin: 'https://evil.com', method: 'OPTIONS', hasRequestMethod: true),
            $this->neverCalledHandler(),
        );

        self::assertSame($response, $result);
        self::assertSame([], $headers);
    }

    #[Test]
    public function testOptionsWithoutRequestMethodIsTreatedAsActualRequest(): void
    {
        $headers    = [];
        $response   = $this->captureResponse($headers);
        $config     = new CorsConfig(allowedOrigins: ['https://example.com']);
        $middleware = new CorsMiddleware($config, $this->unusedFactory());

        $middleware->process(
            $this->request(origin: 'https://example.com', method: 'OPTIONS', hasRequestMethod: false),
            $this->handlerReturning($response),
        );

        self::assertSame('https://example.com', $headers['Access-Control-Allow-Origin']);
        self::assertArrayNotHasKey('Access-Control-Allow-Methods', $headers);
    }

    /**
     * @param array<string, string> $headers
     */
    private function captureResponse(array &$headers): ResponseInterface
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withHeader')->willReturnCallback(
            function (string $name, string $value) use (&$headers, $response): ResponseInterface {
                $headers[$name] = $value;

                return $response;
            },
        );
        $response->method('withAddedHeader')->willReturnCallback(
            function (string $name, string $value) use (&$headers, $response): ResponseInterface {
                $headers[$name] = isset($headers[$name]) ? $headers[$name] . ', ' . $value : $value;

                return $response;
            },
        );

        return $response;
    }

    private function request(string $origin, string $method = 'GET', bool $hasRequestMethod = false): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getHeaderLine')->willReturnMap([['Origin', $origin]]);
        $request->method('getMethod')->willReturn($method);
        $request->method('hasHeader')->willReturnMap([['Access-Control-Request-Method', $hasRequestMethod]]);

        return $request;
    }

    private function handlerReturning(ResponseInterface $response): RequestHandlerInterface
    {
        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        return $handler;
    }

    private function neverCalledHandler(): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        return $handler;
    }

    private function unusedFactory(): ResponseFactoryInterface
    {
        return $this->createStub(ResponseFactoryInterface::class);
    }
}
