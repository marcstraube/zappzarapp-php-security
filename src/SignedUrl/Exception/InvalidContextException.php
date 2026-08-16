<?php

declare(strict_types=1);

namespace Zappzarapp\Security\SignedUrl\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a context binding value fails validation
 */
final class InvalidContextException extends InvalidArgumentException
{
    /**
     * Create for a context value containing control characters
     * (header injection guard)
     */
    public static function containsControlCharacters(): self
    {
        return new self('Context value must not contain control characters');
    }
}
