<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a security header value is invalid
 *
 * Prevents header injection attacks via control characters.
 */
final class InvalidHeaderValueException extends InvalidArgumentException
{
    /**
     * Create exception for control character in header value
     */
    public static function containsControlCharacter(string $header, string $value): self
    {
        // Escape all control characters for safe display
        $escaped = preg_replace_callback(
            '/[\x00-\x1F]/',
            static fn(array $m): string => '\\x' . strtoupper(bin2hex($m[0])),
            $value
        ) ?? $value;

        return new self(sprintf(
            'Header "%s" value contains control character which could lead to header injection: %s',
            $header,
            $escaped
        ));
    }

    /**
     * Create exception for invalid HSTS max-age
     */
    public static function invalidMaxAge(int $maxAge): self
    {
        return new self(sprintf(
            'HSTS max-age must be a non-negative integer, got: %d',
            $maxAge
        ));
    }

    /**
     * Create exception for HSTS preload without includeSubDomains
     */
    public static function preloadRequiresIncludeSubDomains(): self
    {
        return new self(
            'HSTS preload requires includeSubDomains to be enabled'
        );
    }

    /**
     * Create exception for HSTS preload with insufficient max-age
     */
    public static function preloadRequiresMinMaxAge(int $minAge, int $actualAge): self
    {
        return new self(sprintf(
            'HSTS preload requires max-age of at least %d seconds, got: %d',
            $minAge,
            $actualAge
        ));
    }

    /**
     * Create exception for invalid permission directive allowlist
     */
    public static function invalidPermissionAllowlist(string $feature, string $reason): self
    {
        return new self(sprintf(
            'Invalid allowlist for permission "%s": %s',
            $feature,
            $reason
        ));
    }

    /**
     * Create exception for invalid origin in permission allowlist
     */
    public static function invalidOrigin(string $origin): self
    {
        return new self(sprintf(
            'Invalid origin format: "%s" (expected: scheme://host or scheme://host:port)',
            $origin
        ));
    }
}
