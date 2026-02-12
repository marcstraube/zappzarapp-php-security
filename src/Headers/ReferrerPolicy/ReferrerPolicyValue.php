<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\ReferrerPolicy;

/**
 * Referrer-Policy values
 *
 * Controls how much referrer information is included with requests.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
 */
enum ReferrerPolicyValue: string
{
    /**
     * No referrer information is sent
     *
     * Most private. Never sends the Referer header.
     */
    case NO_REFERRER = 'no-referrer';

    /**
     * No referrer when downgrading security (HTTPS -> HTTP)
     *
     * Sends full referrer for same-protocol or upgrade, none for downgrade.
     */
    case NO_REFERRER_WHEN_DOWNGRADE = 'no-referrer-when-downgrade';

    /**
     * Only sends origin (no path or query)
     *
     * Sends "https://example.com/" instead of "https://example.com/page?query".
     */
    case ORIGIN = 'origin';

    /**
     * Only sends origin for cross-origin requests
     *
     * Full referrer for same-origin, origin only for cross-origin.
     */
    case ORIGIN_WHEN_CROSS_ORIGIN = 'origin-when-cross-origin';

    /**
     * Full referrer for same-origin requests only
     *
     * No referrer for cross-origin requests.
     */
    case SAME_ORIGIN = 'same-origin';

    /**
     * Origin only, never downgrade
     *
     * Origin for HTTPS->HTTPS, nothing for HTTPS->HTTP.
     * Recommended for most applications.
     */
    case STRICT_ORIGIN = 'strict-origin';

    /**
     * Full for same-origin, origin for cross-origin, none for downgrade
     *
     * Most commonly recommended policy. Default in many browsers.
     * Balances privacy and functionality.
     */
    case STRICT_ORIGIN_WHEN_CROSS_ORIGIN = 'strict-origin-when-cross-origin';

    /**
     * Always send full referrer
     *
     * SECURITY WARNING: Sends complete URL including path and query parameters
     * to ALL origins, even over insecure HTTP connections. This can leak:
     * - Session tokens in URLs
     * - Search queries and filters
     * - Private document paths
     * - Internal application structure
     *
     * Only use if absolutely required and you understand the privacy implications.
     * Prefer STRICT_ORIGIN_WHEN_CROSS_ORIGIN for most applications.
     */
    case UNSAFE_URL = 'unsafe-url';

    /**
     * Get the header value
     */
    public function headerValue(): string
    {
        return $this->value;
    }
}
