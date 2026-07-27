<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a secret name fails validation
 *
 * Secret names are used to build file paths and environment variable names,
 * so invalid characters (path separators, control characters) are rejected
 * to prevent path traversal and injection attacks. Rejected names are never
 * echoed back in exception messages to avoid log injection.
 */
final class InvalidSecretNameException extends InvalidArgumentException
{
    /**
     * Create for an empty secret name
     */
    public static function emptyName(): self
    {
        return new self('Secret name must not be empty');
    }

    /**
     * Create for a secret name exceeding the maximum length
     */
    public static function tooLong(int $maxLength): self
    {
        return new self(sprintf(
            'Secret name must not exceed %d characters',
            $maxLength
        ));
    }

    /**
     * Create for a secret name containing invalid characters
     */
    public static function invalidCharacters(): self
    {
        return new self(
            'Secret name contains invalid characters '
            . '(allowed: A-Z, a-z, 0-9, ".", "_", "-"; must start with an alphanumeric character)'
        );
    }
}
