<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive
 * @noinspection PhpComposerExtensionStubsInspection psr/http-server-middleware is optional (suggest)
 */

declare(strict_types=1);

namespace Zappzarapp\Security\Middleware;

use Override;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zappzarapp\Security\Cors\CorsConfig;

/**
 * PSR-15 middleware for Cross-Origin Resource Sharing (CORS)
 *
 * Requests without an Origin header pass through untouched. For cross-origin
 * requests the configured CORS response headers are applied; preflight
 * (OPTIONS) requests carrying an Access-Control-Request-Method header are
 * answered directly with a 204 response.
 *
 * When the request origin is not permitted no CORS headers are added, leaving
 * the browser to block the response.
 */
final readonly class CorsMiddleware implements MiddlewareInterface
{
    public function __construct(
        private CorsConfig $config,
        private ResponseFactoryInterface $responseFactory,
    ) {
    }

    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $origin = $request->getHeaderLine('Origin');

        if ($origin === '') {
            return $handler->handle($request);
        }

        $allowOrigin = $this->config->resolveAllowOrigin($origin);

        if ($this->isPreflight($request)) {
            $response = $this->responseFactory->createResponse(204);

            return $allowOrigin === null
                ? $response
                : $this->applyPreflightHeaders($response, $allowOrigin);
        }

        $response = $handler->handle($request);

        return $allowOrigin === null
            ? $response
            : $this->applyActualHeaders($response, $allowOrigin);
    }

    private function isPreflight(ServerRequestInterface $request): bool
    {
        return $request->getMethod() === 'OPTIONS'
            && $request->hasHeader('Access-Control-Request-Method');
    }

    private function applyPreflightHeaders(ResponseInterface $response, string $allowOrigin): ResponseInterface
    {
        $response = $this->applyOriginHeaders($response, $allowOrigin);

        if ($this->config->allowedMethods !== []) {
            $response = $response->withHeader(
                'Access-Control-Allow-Methods',
                implode(', ', $this->config->allowedMethods),
            );
        }

        if ($this->config->allowedHeaders !== []) {
            $response = $response->withHeader(
                'Access-Control-Allow-Headers',
                implode(', ', $this->config->allowedHeaders),
            );
        }

        if ($this->config->maxAge > 0) {
            return $response->withHeader('Access-Control-Max-Age', (string) $this->config->maxAge);
        }

        return $response;
    }

    private function applyActualHeaders(ResponseInterface $response, string $allowOrigin): ResponseInterface
    {
        $response = $this->applyOriginHeaders($response, $allowOrigin);

        if ($this->config->exposedHeaders !== []) {
            return $response->withHeader(
                'Access-Control-Expose-Headers',
                implode(', ', $this->config->exposedHeaders),
            );
        }

        return $response;
    }

    private function applyOriginHeaders(ResponseInterface $response, string $allowOrigin): ResponseInterface
    {
        $response = $response->withHeader('Access-Control-Allow-Origin', $allowOrigin);

        if ($allowOrigin !== '*') {
            $response = $response->withAddedHeader('Vary', 'Origin');
        }

        if ($this->config->allowCredentials) {
            return $response->withHeader('Access-Control-Allow-Credentials', 'true');
        }

        return $response;
    }
}
