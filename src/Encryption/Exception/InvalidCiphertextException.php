<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a ciphertext fails structural validation
 *
 * Structural errors (wrong format, truncation) are detected before any
 * cryptographic operation. Authentication failures throw
 * DecryptionException instead.
 */
final class InvalidCiphertextException extends InvalidArgumentException
{
    /**
     * Create for an unsupported or missing format prefix
     */
    public static function unsupportedFormat(string $expectedPrefix): self
    {
        return new self(sprintf(
            'Ciphertext format not supported (expected "%s" prefix)',
            $expectedPrefix
        ));
    }

    /**
     * Create for a payload that is not valid base64
     */
    public static function invalidEncoding(): self
    {
        return new self('Ciphertext payload is not valid base64');
    }

    /**
     * Create for a payload too short to contain nonce and authentication tag
     */
    public static function truncated(int $minimumBytes, int $actualBytes): self
    {
        return new self(sprintf(
            'Ciphertext payload is truncated (expected at least %d bytes, got %d bytes)',
            $minimumBytes,
            $actualBytes
        ));
    }
}
