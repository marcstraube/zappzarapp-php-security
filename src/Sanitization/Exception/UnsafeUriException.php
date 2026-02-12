<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Exception;

use RuntimeException;

/**
 * Exception thrown when a URI is unsafe
 */
final class UnsafeUriException extends RuntimeException
{
    /**
     * Create for blocked scheme
     */
    public static function blockedScheme(string $scheme): self
    {
        return new self(sprintf(
            'URI scheme "%s" is not allowed',
            $scheme
        ));
    }

    /**
     * Create for invalid URI
     */
    public static function invalidUri(string $uri): self
    {
        return new self(sprintf(
            'Invalid URI: %s',
            $uri
        ));
    }

    /**
     * Create for blocked host
     */
    public static function blockedHost(string $host): self
    {
        return new self(sprintf(
            'URI host "%s" is not allowed',
            $host
        ));
    }
}
