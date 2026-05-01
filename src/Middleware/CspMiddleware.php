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
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\HeaderBuilder;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;
use Zappzarapp\Security\Csp\Nonce\NonceProvider;

/**
 * PSR-15 middleware that applies Content-Security-Policy headers
 *
 * Stores the NonceProvider in the request attribute 'csp-nonce' for template access.
 */
final readonly class CspMiddleware implements MiddlewareInterface
{
    public const string NONCE_ATTRIBUTE = 'csp-nonce';

    private NonceProvider $nonceProvider;

    public function __construct(
        private CspDirectives $directives,
        ?NonceProvider $nonceProvider = null,
        private bool $reportOnly = false,
    ) {
        $this->nonceProvider = $nonceProvider ?? new NonceGenerator();
    }

    /**
     * @throws RandomException
     */
    #[Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $request  = $request->withAttribute(self::NONCE_ATTRIBUTE, $this->nonceProvider);
        $response = $handler->handle($request);

        $headerValue = HeaderBuilder::build($this->directives, $this->nonceProvider);
        $headerName  = $this->reportOnly
            ? HeaderBuilder::HEADER_CSP_REPORT_ONLY
            : HeaderBuilder::HEADER_CSP;

        return $response->withHeader($headerName, $headerValue);
    }
}
