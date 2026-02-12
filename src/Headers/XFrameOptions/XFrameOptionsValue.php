<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\XFrameOptions;

/**
 * X-Frame-Options values
 *
 * Controls whether the page can be displayed in a frame, iframe, embed, or object.
 * Protects against clickjacking attacks.
 *
 * Note: Consider using CSP frame-ancestors directive instead, which is more flexible.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
 */
enum XFrameOptionsValue: string
{
    /**
     * Page cannot be displayed in a frame
     *
     * Most secure. Blocks all framing attempts.
     */
    case DENY = 'DENY';

    /**
     * Page can only be framed by same origin
     *
     * Allows framing only from same domain.
     */
    case SAMEORIGIN = 'SAMEORIGIN';

    /**
     * Get the header value
     */
    public function headerValue(): string
    {
        return $this->value;
    }
}
