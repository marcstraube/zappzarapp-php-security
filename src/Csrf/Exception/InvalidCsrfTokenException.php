<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a CSRF token is malformed or invalid
 */
final class InvalidCsrfTokenException extends InvalidArgumentException
{
    /**
     * Create exception for empty token
     */
    public static function emptyToken(): self
    {
        return new self('CSRF token cannot be empty');
    }

    /**
     * Create exception for invalid format
     */
    public static function invalidFormat(string $token, string $reason): self
    {
        return new self(sprintf(
            'CSRF token has invalid format (%s): %s',
            $reason,
            str_replace(["\r", "\n"], ['\\r', '\\n'], $token)
        ));
    }

    /**
     * Create exception for invalid base64 encoding
     */
    public static function invalidBase64(string $token): self
    {
        return new self(sprintf(
            'CSRF token is not valid base64: %s',
            $token
        ));
    }

    /**
     * Create exception for insufficient entropy
     */
    public static function insufficientEntropy(int $expectedBytes, int $actualBytes): self
    {
        return new self(sprintf(
            'CSRF token has insufficient entropy: expected %d bytes, got %d',
            $expectedBytes,
            $actualBytes
        ));
    }
}
