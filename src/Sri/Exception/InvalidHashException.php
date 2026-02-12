<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sri\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when an SRI hash is invalid
 */
final class InvalidHashException extends InvalidArgumentException
{
    /**
     * Create for invalid format
     */
    public static function invalidFormat(string $hash): self
    {
        return new self(sprintf(
            'Invalid SRI hash format: %s',
            $hash
        ));
    }

    /**
     * Create for unsupported algorithm
     */
    public static function unsupportedAlgorithm(string $algorithm): self
    {
        return new self(sprintf(
            'Unsupported SRI hash algorithm: %s (supported: sha384, sha512)',
            $algorithm
        ));
    }

    /**
     * Create for invalid base64
     */
    public static function invalidBase64(string $hash): self
    {
        return new self(sprintf(
            'SRI hash contains invalid base64: %s',
            $hash
        ));
    }
}
