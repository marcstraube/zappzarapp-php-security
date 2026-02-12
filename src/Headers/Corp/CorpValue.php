<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Corp;

/**
 * Cross-Origin-Resource-Policy (CORP) values
 *
 * CORP indicates which origins are allowed to include a resource.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy
 */
enum CorpValue: string
{
    /**
     * Only same-origin requests can load the resource
     *
     * Most restrictive. Blocks cross-origin and cross-site requests.
     */
    case SAME_ORIGIN = 'same-origin';

    /**
     * Only same-site requests can load the resource
     *
     * Allows subdomains (example.com can access assets.example.com).
     */
    case SAME_SITE = 'same-site';

    /**
     * Any origin can load the resource
     *
     * Least restrictive. Use only for public resources (e.g., public CDN assets).
     */
    case CROSS_ORIGIN = 'cross-origin';

    /**
     * Get the header value
     */
    public function headerValue(): string
    {
        return $this->value;
    }
}
