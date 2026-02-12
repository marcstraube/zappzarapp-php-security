<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Exception;

use RuntimeException;

/**
 * Exception thrown when CSRF token validation fails
 *
 * This indicates a potential CSRF attack or session expiration.
 */
final class CsrfTokenMismatchException extends RuntimeException
{
    /**
     * Create exception for missing token
     */
    public static function missingToken(): self
    {
        return new self('CSRF token is missing from the request');
    }

    /**
     * Create exception for expired token
     */
    public static function expiredToken(): self
    {
        return new self('CSRF token has expired');
    }

    /**
     * Create exception for token mismatch
     */
    public static function tokenMismatch(): self
    {
        return new self('CSRF token validation failed');
    }

    /**
     * Create exception for no stored token
     */
    public static function noStoredToken(): self
    {
        return new self('No CSRF token found in storage');
    }
}
