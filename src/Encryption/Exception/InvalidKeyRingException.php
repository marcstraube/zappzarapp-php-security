<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a key ring fails structural validation
 *
 * Key material is never echoed back in exception messages.
 */
final class InvalidKeyRingException extends InvalidArgumentException
{
    /**
     * Create for a ring without any keys
     */
    public static function empty(): self
    {
        return new self('Key ring must contain at least one key');
    }

    /**
     * Create for a key version outside the supported integer range
     */
    public static function invalidVersion(int $version, int $maximum): self
    {
        return new self(sprintf(
            'Key version must be between 1 and %d, got %d',
            $maximum,
            $version
        ));
    }

    /**
     * Create for an active version that has no key in the ring
     */
    public static function unknownActiveVersion(int $version): self
    {
        return new self(sprintf(
            'Active key version %d is not present in the key ring',
            $version
        ));
    }

    /**
     * Create for an attempt to remove the active key
     */
    public static function cannotRemoveActiveKey(int $version): self
    {
        return new self(sprintf(
            'Cannot remove key version %d while it is the active encryption key',
            $version
        ));
    }
}
