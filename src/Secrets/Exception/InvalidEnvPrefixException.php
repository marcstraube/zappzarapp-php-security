<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when an environment variable prefix fails validation
 *
 * The prefix is embedded in environment variable lookups and error messages,
 * so control characters and other unexpected input are rejected. The rejected
 * prefix is never echoed back to avoid log injection.
 */
final class InvalidEnvPrefixException extends InvalidArgumentException
{
    /**
     * Create for a prefix containing invalid characters
     */
    public static function invalidCharacters(): self
    {
        return new self(
            'Environment variable prefix contains invalid characters '
            . '(allowed: A-Z, 0-9, "_"; must start with a letter)'
        );
    }
}
