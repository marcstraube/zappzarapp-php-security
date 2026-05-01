<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Middleware;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zappzarapp\Security\Csrf\CsrfConfig;
use Zappzarapp\Security\Csrf\CsrfProtection;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Storage\ArrayCsrfStorage;
use Zappzarapp\Security\Csrf\Token\CsrfToken;
use Zappzarapp\Security\Csrf\Token\CsrfTokenGenerator;
use Zappzarapp\Security\Middleware\CsrfMiddleware;

#[CoversClass(CsrfMiddleware::class)]
#[UsesClass(CsrfProtection::class)]
#[UsesClass(CsrfConfig::class)]
#[UsesClass(ArrayCsrfStorage::class)]
#[UsesClass(CsrfToken::class)]
#[UsesClass(CsrfTokenGenerator::class)]
#[UsesClass(CsrfTokenMismatchException::class)]
final class CsrfMiddlewareTest extends TestCase
{
    private CsrfProtection $protection;

    private CsrfMiddleware $middleware;

    protected function setUp(): void
    {
        $this->protection = CsrfProtection::synchronizer(new ArrayCsrfStorage());
        $this->middleware = new CsrfMiddleware($this->protection);
    }

    #[Test]
    public function testGetRequestPassesThrough(): void
    {
        $request  = $this->createRequest('GET');
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testHeadRequestPassesThrough(): void
    {
        $request  = $this->createRequest('HEAD');
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $result = $this->middleware->process($request, $handler);

        $this->assertSame($response, $result);
    }

    #[Test]
    public function testOptionsRequestPassesThrough(): void
    {
        $request  = $this->createRequest('OPTIONS');
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $result = $this->middleware->process($request, $handler);

        $this->assertSame($response, $result);
    }

    #[Test]
    public function testStoresTokenInRequestAttribute(): void
    {
        $request  = $this->createRequest('GET');
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $storedToken = null;

        $request->method('withAttribute')
            ->willReturnCallback(function (string $name, mixed $value) use (&$storedToken, $request): ServerRequestInterface {
                if ($name === CsrfMiddleware::TOKEN_ATTRIBUTE) {
                    $storedToken = $value;
                }

                return $request;
            });

        $this->middleware->process($request, $handler);

        $this->assertInstanceOf(CsrfToken::class, $storedToken);
    }

    #[Test]
    public function testPostRequestValidatesTokenFromHeader(): void
    {
        $token = $this->protection->token();

        $request  = $this->createRequest('POST', headerToken: (string) $token);
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPostRequestValidatesTokenFromBody(): void
    {
        $token = $this->protection->token();

        $request  = $this->createRequest('POST', bodyToken: (string) $token);
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPostRequestThrowsOnMissingToken(): void
    {
        $this->expectException(CsrfTokenMismatchException::class);

        $request  = $this->createRequest('POST');
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPostRequestThrowsOnInvalidToken(): void
    {
        // Generate a valid token first so there's something stored
        $this->protection->token();

        $this->expectException(InvalidCsrfTokenException::class);

        $request  = $this->createRequest('POST', headerToken: 'invalid-token');
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testDeleteRequestRequiresToken(): void
    {
        $token = $this->protection->token();

        $request  = $this->createRequest('DELETE', headerToken: (string) $token);
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPutRequestRequiresToken(): void
    {
        $this->expectException(CsrfTokenMismatchException::class);

        $request  = $this->createRequest('PUT');
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testHeaderTokenTakesPriorityOverBody(): void
    {
        $token = $this->protection->token();

        // Both header and body have tokens, header should be used
        $request  = $this->createRequest('POST', headerToken: (string) $token, bodyToken: 'wrong-token');
        $response = $this->createStub(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    private function createRequest(
        string $method,
        ?string $headerToken = null,
        ?string $bodyToken = null,
    ): ServerRequestInterface&MockObject {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn($method);
        $request->method('withAttribute')->willReturn($request);
        $request->method('getHeaderLine')
            ->willReturnCallback(fn (string $name): string => $name === $this->protection->headerName() && $headerToken !== null
                ? $headerToken
                : '');

        $body = $bodyToken !== null ? [$this->protection->fieldName() => $bodyToken] : [];
        $request->method('getParsedBody')->willReturn($body);

        return $request;
    }
}
