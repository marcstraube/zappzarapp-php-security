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
use Zappzarapp\Security\Headers\Builder\SecurityHeadersBuilder;
use Zappzarapp\Security\Headers\SecurityHeaders;

/**
 * PSR-15 middleware that applies security headers to responses
 */
final readonly class SecurityHeadersMiddleware implements MiddlewareInterface
{
    private SecurityHeadersBuilder $builder;

    public function __construct(SecurityHeaders $headers)
    {
        $this->builder = SecurityHeadersBuilder::from($headers);
    }

    /**
     * @throws RandomException
     */
    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);

        foreach ($this->builder->build() as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }
}
