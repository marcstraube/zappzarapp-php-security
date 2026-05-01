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
use Zappzarapp\Security\Csrf\CsrfProtection;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;

/**
 * PSR-15 middleware for CSRF protection (Synchronizer Token Pattern)
 *
 * Safe methods (GET, HEAD, OPTIONS) pass through with the CSRF token
 * stored in the request attribute 'csrf-token'.
 *
 * State-changing methods (POST, PUT, DELETE, PATCH) validate the CSRF
 * token from the request header or parsed body field.
 *
 * @throws CsrfTokenMismatchException When token validation fails
 * @throws InvalidCsrfTokenException When token format is invalid
 */
final readonly class CsrfMiddleware implements MiddlewareInterface
{
    public const string TOKEN_ATTRIBUTE = 'csrf-token';

    private const array SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

    public function __construct(
        private CsrfProtection $protection,
    ) {
    }

    /**
     * @throws RandomException
     */
    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!in_array($request->getMethod(), self::SAFE_METHODS, true)) {
            $this->validateToken($request);
        }

        $request = $request->withAttribute(self::TOKEN_ATTRIBUTE, $this->protection->token());

        return $handler->handle($request);
    }

    /**
     * @throws CsrfTokenMismatchException
     * @throws InvalidCsrfTokenException
     * @throws RandomException
     */
    private function validateToken(ServerRequestInterface $request): void
    {
        $token = $this->extractToken($request);

        $this->protection->validate($token);
    }

    private function extractToken(ServerRequestInterface $request): string
    {
        $headerName = $this->protection->headerName();
        $header     = $request->getHeaderLine($headerName);

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
}
