<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Coep;

/**
 * Cross-Origin-Embedder-Policy (COEP) values
 *
 * COEP prevents loading cross-origin resources that don't explicitly grant permission.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy
 */
enum CoepValue: string
{
    /**
     * Allows fetching cross-origin resources without CORS or CORP
     *
     * Default browser behavior. No restrictions.
     */
    case UNSAFE_NONE = 'unsafe-none';

    /**
     * Only allows cross-origin resources with CORS or CORP headers
     *
     * Resources must include Cross-Origin-Resource-Policy or CORS headers.
     * Required for using SharedArrayBuffer.
     *
     * IMPORTANT: When using this value, ALL cross-origin resources (images, scripts,
     * stylesheets, fonts, etc.) must either:
     * - Include a Cross-Origin-Resource-Policy header (same-origin, same-site, or cross-origin)
     * - Be served with appropriate CORS headers (Access-Control-Allow-Origin)
     *
     * Resources without these headers will be blocked silently by the browser.
     * Test thoroughly before deploying, especially with third-party resources.
     *
     * @see CorpValue For the Cross-Origin-Resource-Policy header values
     */
    case REQUIRE_CORP = 'require-corp';

    /**
     * Same as require-corp but allows credentialless fetches
     *
     * Cross-origin no-cors requests are sent without credentials.
     * Useful when you need COEP but some resources don't support CORS.
     */
    case CREDENTIALLESS = 'credentialless';

    /**
     * Get the header value
     */
    public function headerValue(): string
    {
        return $this->value;
    }
}
