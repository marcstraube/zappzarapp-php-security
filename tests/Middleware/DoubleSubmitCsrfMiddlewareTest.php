<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Middleware;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Random\RandomException;
use Zappzarapp\Security\Cookie\CookieBuilder;
use Zappzarapp\Security\Cookie\CookieOptions;
use Zappzarapp\Security\Cookie\CookieValidator;
use Zappzarapp\Security\Cookie\SameSitePolicy;
use Zappzarapp\Security\Cookie\SecureCookie;
use Zappzarapp\Security\Csrf\CsrfConfig;
use Zappzarapp\Security\Csrf\CsrfProtection;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Pattern\DoubleSubmitCookiePattern;
use Zappzarapp\Security\Csrf\Token\CsrfToken;
use Zappzarapp\Security\Csrf\Token\CsrfTokenGenerator;
use Zappzarapp\Security\Middleware\DoubleSubmitCsrfMiddleware;

#[CoversClass(DoubleSubmitCsrfMiddleware::class)]
#[UsesClass(CsrfProtection::class)]
#[UsesClass(CsrfConfig::class)]
#[UsesClass(DoubleSubmitCookiePattern::class)]
#[UsesClass(CsrfToken::class)]
#[UsesClass(CsrfTokenGenerator::class)]
#[UsesClass(CsrfTokenMismatchException::class)]
#[UsesClass(CookieBuilder::class)]
#[UsesClass(CookieOptions::class)]
#[UsesClass(CookieValidator::class)]
#[UsesClass(SecureCookie::class)]
#[UsesClass(SameSitePolicy::class)]
final class DoubleSubmitCsrfMiddlewareTest extends TestCase
{
    private const string SECRET = 'this-is-a-32-byte-test-secret!!!';

    private CsrfProtection $protection;

    private DoubleSubmitCsrfMiddleware $middleware;

    protected function setUp(): void
    {
        $this->protection = CsrfProtection::doubleSubmit(self::SECRET);
        $this->middleware = new DoubleSubmitCsrfMiddleware($this->protection);
    }

    #[Test]
    public function testSafeRequestPassesThrough(): void
    {
        $request  = $this->createRequest('GET');
        $response = $this->createResponse();

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testHeadAndOptionsPassThrough(): void
    {
        foreach (['HEAD', 'OPTIONS'] as $method) {
            $request  = $this->createRequest($method);
            $response = $this->createResponse();

            $handler = $this->createStub(RequestHandlerInterface::class);
            $handler->method('handle')->willReturn($response);

            $this->assertSame($response, $this->middleware->process($request, $handler));
        }
    }

    #[Test]
    public function testExposesSignedTokenInRequestAttribute(): void
    {
        $request  = $this->createRequest('GET');
        $response = $this->createResponse();

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($response);

        $storedToken = null;

        $request->method('withAttribute')
            ->willReturnCallback(function (string $name, mixed $value) use (&$storedToken, $request): ServerRequestInterface {
                if ($name === DoubleSubmitCsrfMiddleware::TOKEN_ATTRIBUTE) {
                    $storedToken = $value;
                }

                return $request;
            });

        $this->middleware->process($request, $handler);

        $this->assertIsString($storedToken);
        // Signed token has the "token.signature" shape
        $this->assertStringContainsString('.', $storedToken);
    }

    #[Test]
    public function testResponseCarriesReadableCsrfCookie(): void
    {
        $setCookie = '';

        $request = $this->createRequest('GET');
        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($this->createResponse($setCookie));

        $this->middleware->process($request, $handler);

        $this->assertNotSame('', $setCookie);
        $this->assertStringStartsWith($this->protection->cookieName() . '=', $setCookie);
        $this->assertStringContainsString('SameSite=Strict', $setCookie);
        $this->assertStringContainsString('Secure', $setCookie);
        // Double-submit cookie must be readable by JavaScript
        $this->assertStringNotContainsString('HttpOnly', $setCookie);
    }

    #[Test]
    public function testEmittedCookieAndAttributeFormValidPair(): void
    {
        $setCookie   = '';
        $signedToken = null;

        $request = $this->createRequest('GET');
        $request->method('withAttribute')
            ->willReturnCallback(function (string $name, mixed $value) use (&$signedToken, $request): ServerRequestInterface {
                if ($name === DoubleSubmitCsrfMiddleware::TOKEN_ATTRIBUTE) {
                    $signedToken = $value;
                }

                return $request;
            });

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($this->createResponse($setCookie));

        $this->middleware->process($request, $handler);

        $this->assertNotSame('', $setCookie);
        $this->assertIsString($signedToken);

        $cookieToken = $this->cookieValue($setCookie);

        // The pair emitted on a safe request must validate on the next request
        $this->assertTrue($this->protection->isValidDoubleSubmit($cookieToken, $signedToken));
    }

    #[Test]
    public function testInsecureFlagOmitsSecureAttribute(): void
    {
        $middleware = new DoubleSubmitCsrfMiddleware($this->protection, secure: false);

        $setCookie = '';
        $request   = $this->createRequest('GET');
        $handler   = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($this->createResponse($setCookie));

        $middleware->process($request, $handler);

        $this->assertNotSame('', $setCookie);
        $this->assertStringNotContainsString('Secure', $setCookie);
    }

    #[Test]
    public function testPostValidatesCookieAgainstHeaderToken(): void
    {
        [$cookie, $signed] = $this->validPair();

        $request  = $this->createRequest('POST', cookieToken: $cookie, headerToken: $signed);
        $response = $this->createResponse();

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPostValidatesCookieAgainstBodyToken(): void
    {
        [$cookie, $signed] = $this->validPair();

        $request  = $this->createRequest('POST', cookieToken: $cookie, bodyToken: $signed);
        $response = $this->createResponse();

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testHeaderTokenTakesPriorityOverBody(): void
    {
        [$cookie, $signed] = $this->validPair();

        $request  = $this->createRequest('POST', cookieToken: $cookie, headerToken: $signed, bodyToken: 'wrong.signature');
        $response = $this->createResponse();

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')->willReturn($response);

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPostThrowsOnMissingCookieToken(): void
    {
        [, $signed] = $this->validPair();

        $this->expectException(CsrfTokenMismatchException::class);

        $request = $this->createRequest('POST', headerToken: $signed);
        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($this->createResponse());

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPostThrowsWhenCookieTokenIsNotAString(): void
    {
        [, $signed] = $this->validPair();

        $this->expectException(CsrfTokenMismatchException::class);

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getCookieParams')->willReturn([$this->protection->cookieName() => ['array-not-string']]);
        $request->method('getHeaderLine')->willReturn($signed);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($this->createResponse());

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPostThrowsOnMissingSubmittedToken(): void
    {
        [$cookie] = $this->validPair();

        $this->expectException(CsrfTokenMismatchException::class);

        $request = $this->createRequest('POST', cookieToken: $cookie);
        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($this->createResponse());

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPostThrowsWhenBodyTokenIsNotAString(): void
    {
        [$cookie] = $this->validPair();

        $this->expectException(CsrfTokenMismatchException::class);

        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn('POST');
        $request->method('getCookieParams')->willReturn([$this->protection->cookieName() => $cookie]);
        $request->method('getHeaderLine')->willReturn('');
        $request->method('getParsedBody')->willReturn([$this->protection->fieldName() => ['not-a-string']]);

        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($this->createResponse());

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPostThrowsOnTokenMismatch(): void
    {
        [$cookie] = $this->validPair();

        $this->expectException(CsrfTokenMismatchException::class);

        $request = $this->createRequest('POST', cookieToken: $cookie, headerToken: 'tampered.signature');
        $handler = $this->createStub(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn($this->createResponse());

        $this->middleware->process($request, $handler);
    }

    #[Test]
    public function testPutAndDeleteRequireValidation(): void
    {
        foreach (['PUT', 'DELETE'] as $method) {
            [$cookie, $signed] = $this->validPair();

            $request  = $this->createRequest($method, cookieToken: $cookie, headerToken: $signed);
            $response = $this->createResponse();

            $handler = $this->createMock(RequestHandlerInterface::class);
            $handler->expects($this->once())->method('handle')->willReturn($response);

            $this->middleware->process($request, $handler);
        }
    }

    /**
     * Produce a matching (raw cookie token, signed token) pair
     *
     * @return array{string, string}
     *
     * @throws RandomException If no suitable random source is available
     */
    private function validPair(): array
    {
        $token = $this->protection->token();

        return [$token->value(), $this->protection->signToken($token)];
    }

    /**
     * Extract the cookie value from a Set-Cookie header string
     */
    private function cookieValue(string $setCookie): string
    {
        $first = explode(';', $setCookie, 2)[0];
        $value = explode('=', $first, 2)[1];

        return rawurldecode($value);
    }

    private function createRequest(
        string $method,
        ?string $cookieToken = null,
        ?string $headerToken = null,
        ?string $bodyToken = null,
    ): ServerRequestInterface&Stub {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getMethod')->willReturn($method);
        $request->method('withAttribute')->willReturn($request);
        $request->method('getCookieParams')->willReturn(
            $cookieToken !== null ? [$this->protection->cookieName() => $cookieToken] : [],
        );
        $request->method('getHeaderLine')
            ->willReturnCallback(fn (string $name): string => $name === $this->protection->headerName() && $headerToken !== null
                ? $headerToken
                : '');
        $request->method('getParsedBody')->willReturn(
            $bodyToken !== null ? [$this->protection->fieldName() => $bodyToken] : [],
        );

        return $request;
    }

    /**
     * Build a response stub that captures the Set-Cookie header it receives
     */
    private function createResponse(string &$setCookie = ''): ResponseInterface&Stub
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('withAddedHeader')
            ->willReturnCallback(function (string $name, mixed $value) use (&$setCookie, $response): ResponseInterface {
                if ($name === 'Set-Cookie' && is_string($value)) {
                    $setCookie = $value;
                }

                return $response;
            });

        return $response;
    }
}
