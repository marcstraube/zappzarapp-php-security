<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Cookie\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when cookie options (path, domain, sameSite) are invalid
 *
 * Used for validation errors in CookieOptions that could lead to
 * HTTP header injection or RFC 6265bis constraint violations.
 */
final class InvalidCookieOptionsException extends InvalidArgumentException
{
    /**
     * Create exception for invalid path characters (header injection prevention)
     */
    public static function invalidPath(string $path): self
    {
        return new self(sprintf(
            'Cookie path "%s" contains invalid characters (CR, LF, semicolon, comma, or null byte)',
            self::truncate($path)
        ));
    }

    /**
     * Create exception for invalid domain characters (header injection prevention)
     */
    public static function invalidDomain(string $domain): self
    {
        return new self(sprintf(
            'Cookie domain "%s" contains invalid characters (CR, LF, semicolon, comma, or null byte)',
            self::truncate($domain)
        ));
    }

    /**
     * Create exception for SameSite=None without Secure flag
     *
     * RFC 6265bis requires Secure flag when using SameSite=None.
     * Modern browsers reject SameSite=None cookies without Secure.
     */
    public static function sameSiteNoneRequiresSecure(): self
    {
        return new self(
            'SameSite=None requires Secure flag. Use withSecure()->withSameSite(SameSitePolicy::NONE) '
            . 'or withSameSiteNone() which automatically enables Secure.'
        );
    }

    /**
     * Truncate long values for safe error message display
     */
    private static function truncate(string $value): string
    {
        $maxLength = 50;

        if (strlen($value) <= $maxLength) {
            return $value;
        }

        return substr($value, 0, $maxLength) . '...';
    }
}
