<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a secret value fails validation
 */
final class InvalidSecretValueException extends InvalidArgumentException
{
    /**
     * Create for an empty secret value
     */
    public static function emptyValue(): self
    {
        return new self('Secret value must not be empty');
    }
}
