<?php

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Exception;

use RuntimeException;

/**
 * Exception thrown when rate limit storage fails
 */
final class StorageException extends RuntimeException
{
    /**
     * Create for connection failure
     */
    public static function connectionFailed(string $reason): self
    {
        return new self(sprintf('Rate limit storage connection failed: %s', $reason));
    }

    /**
     * Create for read failure
     */
    public static function readFailed(string $key, string $reason): self
    {
        return new self(sprintf('Failed to read rate limit for "%s": %s', $key, $reason));
    }

    /**
     * Create for write failure
     */
    public static function writeFailed(string $key, string $reason): self
    {
        return new self(sprintf('Failed to write rate limit for "%s": %s', $key, $reason));
    }
}
