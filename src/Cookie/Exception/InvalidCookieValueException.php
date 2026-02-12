<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Cookie\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a cookie value is invalid
 */
final class InvalidCookieValueException extends InvalidArgumentException
{
    /**
     * Create exception for invalid character
     */
    public static function invalidCharacter(string $value, string $char): self
    {
        return new self(sprintf(
            'Cookie value contains invalid character: %s (in value: %s)',
            $char === ';' ? 'semicolon' : ($char === ',' ? 'comma' : $char),
            substr($value, 0, 50) . (strlen($value) > 50 ? '...' : '')
        ));
    }

    /**
     * Create exception for value too long
     */
    public static function tooLong(int $length, int $maxLength): self
    {
        return new self(sprintf(
            'Cookie value is too long: %d bytes (max: %d bytes)',
            $length,
            $maxLength
        ));
    }
}
