<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp;

/**
 * Common CSP directive values as type-safe constants
 *
 * Provides standard CSP values to avoid magic strings and typos.
 *
 * @psalm-api
 */
enum CspValue: string
{
    case SELF           = "'self'";
    case NONE           = "'none'";
    case UNSAFE_INLINE  = "'unsafe-inline'";
    case UNSAFE_EVAL    = "'unsafe-eval'";
    case STRICT_DYNAMIC = "'strict-dynamic'";
    case DATA           = "data:";
    case BLOB           = "blob:";
    case MEDIASTREAM    = "mediastream:";
    case HTTPS          = "https:";
    case WSS            = "wss:";

    /**
     * Combine multiple CSP values into a single directive string
     *
     * @param CspValue ...$values CSP values to combine
     * @return string Space-separated directive value string
     */
    public static function combine(CspValue ...$values): string
    {
        return implode(' ', array_map(
            static fn(CspValue $value): string => $value->value,
            $values
        ));
    }
}
