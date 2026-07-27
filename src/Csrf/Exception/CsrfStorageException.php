<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Exception;

use RuntimeException;

/**
 * Exception thrown when CSRF token storage fails
 */
final class CsrfStorageException extends RuntimeException
{
    /**
     * Create for read failure
     */
    public static function readFailed(string $key, string $reason): self
    {
        return new self(sprintf('Failed to read CSRF token for "%s": %s', $key, $reason));
    }

    /**
     * Create for write failure
     */
    public static function writeFailed(string $key, string $reason): self
    {
        return new self(sprintf('Failed to write CSRF token for "%s": %s', $key, $reason));
    }
}
