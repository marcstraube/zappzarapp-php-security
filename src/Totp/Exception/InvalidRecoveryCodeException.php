<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when recovery code parameters fail validation
 *
 * Code material is never echoed back in exception messages.
 */
final class InvalidRecoveryCodeException extends InvalidArgumentException
{
    /**
     * Create for a code count outside the supported range
     */
    public static function invalidCount(int $count): self
    {
        return new self(sprintf('Recovery code count must be between 1 and 100, got %d', $count));
    }
}
