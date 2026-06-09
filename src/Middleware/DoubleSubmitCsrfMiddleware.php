<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive
 * @noinspection PhpComposerExtensionStubsInspection psr/http-server-middleware is optional (suggest)
 */

declare(strict_types=1);

namespace Zappzarapp\Security\Middleware;

use Override;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Random\RandomException;
use Zappzarapp\Security\Cookie\CookieBuilder;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieNameException;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieValueException;
use Zappzarapp\Security\Cookie\SameSitePolicy;
use Zappzarapp\Security\Csrf\CsrfProtection;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;

/**
 * PSR-15 middleware for CSRF protection (HMAC-Signed Double Submit Cookie Pattern)
 *
 * Complements {@see CsrfMiddleware} (Synchronizer Token Pattern) for stateless
 * SPA/API setups that cannot rely on server-side session storage.
 *
 * Every response carries a fresh CSRF cookie holding the raw token, while the
 * matching HMAC-signed token is exposed via the request attribute 'csrf-token'
 * for the application to embed in forms or hand to client-side JavaScript.
 *
 * Safe methods (GET, HEAD, OPTIONS) pass through. State-changing methods
 * (POST, PUT, DELETE, PATCH) validate the cookie token against the signed
 * token from the request header or parsed body field before the cookie is
 * rotated.
 *
 * @throws CsrfTokenMismatchException When token validation fails
 * @throws InvalidCsrfTokenException When token format is invalid
 */
final readonly class DoubleSubmitCsrfMiddleware implements MiddlewareInterface
{
    public const string TOKEN_ATTRIBUTE = 'csrf-token';

    private const array SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

    /**
     * @param CsrfProtection $protection CSRF facade created via CsrfProtection::doubleSubmit()
     * @param bool $secure Set the Secure cookie flag (keep true in production)
     */
    public function __construct(
        private CsrfProtection $protection,
        private bool $secure = true,
    ) {
    }

    /**
     * @throws CsrfTokenMismatchException
     * @throws InvalidCsrfTokenException
     * @throws InvalidCookieNameException
     * @throws InvalidCookieValueException
     * @throws RandomException
     */
    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!in_array($request->getMethod(), self::SAFE_METHODS, true)) {
            $this->validateTokens($request);
        }

        $token = $this->protection->token();

        $request  = $request->withAttribute(self::TOKEN_ATTRIBUTE, $this->protection->signToken($token));
        $response = $handler->handle($request);

        return $this->withCsrfCookie($response, $token->value());
    }

    /**
     * @throws CsrfTokenMismatchException
     * @throws InvalidCsrfTokenException
     */
    private function validateTokens(ServerRequestInterface $request): void
    {
        $this->protection->validateDoubleSubmit(
            $this->extractCookieToken($request),
            $this->extractSubmittedToken($request),
        );
    }

    /**
     * @throws CsrfTokenMismatchException If the cookie token is absent
     */
    private function extractCookieToken(ServerRequestInterface $request): string
    {
        $cookies = $request->getCookieParams();
        $name    = $this->protection->cookieName();

        if (isset($cookies[$name]) && is_string($cookies[$name])) {
            return $cookies[$name];
        }

        throw CsrfTokenMismatchException::missingToken();
    }

    /**
     * @throws CsrfTokenMismatchException If neither header nor body carries a token
     */
    private function extractSubmittedToken(ServerRequestInterface $request): string
    {
        $header = $request->getHeaderLine($this->protection->headerName());

        if ($header !== '') {
            return $header;
        }

        $fieldName = $this->protection->fieldName();
        $body      = $request->getParsedBody();

        if (is_array($body) && isset($body[$fieldName]) && is_string($body[$fieldName])) {
            return $body[$fieldName];
        }

        throw CsrfTokenMismatchException::missingToken();
    }

    /**
     * Attach the raw token as a JavaScript-readable cookie on the response
     *
     * @throws InvalidCookieNameException If the configured cookie name is invalid
     * @throws InvalidCookieValueException If the token value is invalid
     */
    private function withCsrfCookie(ResponseInterface $response, string $rawToken): ResponseInterface
    {
        $options = $this->protection->cookieOptions($this->secure);

        $cookie = CookieBuilder::create($options['name'], $rawToken)
            ->expires($options['expires'])
            ->path($options['path'])
            ->secure($options['secure'])
            ->httpOnly($options['httponly'])
            ->sameSite(SameSitePolicy::from($options['samesite']))
            ->build();

        return $response->withAddedHeader('Set-Cookie', $cookie->headerValue());
    }
}
