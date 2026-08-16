<?php

declare(strict_types=1);

namespace Zappzarapp\Security\SignedUrl\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a signed URL lifetime is not a positive number of
 * seconds or exceeds the maximum
 */
final class InvalidLifetimeException extends InvalidArgumentException
{
    /**
     * Create for a lifetime that is zero or negative
     */
    public static function nonPositive(int $lifetimeSeconds): self
    {
        return new self(sprintf(
            'Signed URL lifetime must be a positive number of seconds, got %d',
            $lifetimeSeconds
        ));
    }

    /**
     * Create for a lifetime beyond the maximum (integer overflow guard)
     */
    public static function exceedsMaximum(int $lifetimeSeconds, int $maximumSeconds): self
    {
        return new self(sprintf(
            'Signed URL lifetime must not exceed %d seconds (100 years), got %d',
            $maximumSeconds,
            $lifetimeSeconds
        ));
    }
}
