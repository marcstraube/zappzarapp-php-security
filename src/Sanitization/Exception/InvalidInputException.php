<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when input fails sanitization
 */
final class InvalidInputException extends InvalidArgumentException
{
    /**
     * Create for malformed input
     */
    public static function malformed(string $type, string $reason): self
    {
        return new self(sprintf('Invalid %s input: %s', $type, $reason));
    }

    /**
     * Create for unsafe content
     */
    public static function unsafeContent(string $type, string $reason): self
    {
        return new self(sprintf('Unsafe %s content detected: %s', $type, $reason));
    }

    /**
     * Create for encoding issues
     */
    public static function invalidEncoding(string $expected): self
    {
        return new self(sprintf('Input is not valid %s', $expected));
    }
}
