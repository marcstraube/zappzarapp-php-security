<?php

declare(strict_types=1);

namespace Zappzarapp\Security\SignedUrl\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when signing key material fails validation
 *
 * Key material is never echoed back in exception messages.
 */
final class InvalidSigningKeyException extends InvalidArgumentException
{
    /**
     * Create for key material below the minimum length
     */
    public static function tooShort(int $minimumBytes, int $actualBytes): self
    {
        return new self(sprintf(
            'Signing key must be at least %d bytes, got %d bytes',
            $minimumBytes,
            $actualBytes
        ));
    }

    /**
     * Create for key material that is not valid base64
     */
    public static function invalidEncoding(): self
    {
        return new self('Signing key material is not valid base64');
    }
}
