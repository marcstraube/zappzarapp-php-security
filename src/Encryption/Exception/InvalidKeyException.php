<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when encryption key material fails validation
 *
 * Key material is never echoed back in exception messages.
 */
final class InvalidKeyException extends InvalidArgumentException
{
    /**
     * Create for key material of the wrong length
     */
    public static function invalidLength(int $expectedBytes, int $actualBytes): self
    {
        return new self(sprintf(
            'Encryption key must be exactly %d bytes, got %d bytes',
            $expectedBytes,
            $actualBytes
        ));
    }

    /**
     * Create for key material that is not valid base64
     */
    public static function invalidEncoding(): self
    {
        return new self('Encryption key material is not valid base64');
    }
}
