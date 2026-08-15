<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when TOTP secret material fails validation
 *
 * Secret material is never echoed back in exception messages.
 */
final class InvalidTotpSecretException extends InvalidArgumentException
{
    /**
     * Create for secret material below the RFC 4226 minimum
     */
    public static function tooShort(int $minimumBytes, int $actualBytes): self
    {
        return new self(sprintf(
            'TOTP secret must be at least %d bytes (160 bit), got %d bytes',
            $minimumBytes,
            $actualBytes
        ));
    }
}
