<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Coop;

/**
 * Cross-Origin-Opener-Policy (COOP) values
 *
 * COOP controls sharing of browsing context group with cross-origin documents.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy
 */
enum CoopValue: string
{
    /**
     * Allows document to be added to opener's browsing context group
     *
     * Default browser behavior. No isolation.
     */
    case UNSAFE_NONE = 'unsafe-none';

    /**
     * Isolates browsing context group (breaks opener reference)
     *
     * The most secure option. Cross-origin documents cannot access window.opener.
     * Required for using SharedArrayBuffer.
     */
    case SAME_ORIGIN = 'same-origin';

    /**
     * Same-origin with allowance for popups
     *
     * Isolates browsing context but allows popups from same-origin to keep opener.
     * Useful when you need to maintain popups but want COOP benefits.
     */
    case SAME_ORIGIN_ALLOW_POPUPS = 'same-origin-allow-popups';

    /**
     * Get the header value
     */
    public function headerValue(): string
    {
        return $this->value;
    }
}
