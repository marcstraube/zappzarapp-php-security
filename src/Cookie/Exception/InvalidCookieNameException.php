<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Cookie\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a cookie name is invalid
 */
final class InvalidCookieNameException extends InvalidArgumentException
{
    /**
     * Create exception for empty name
     */
    public static function emptyName(): self
    {
        return new self('Cookie name cannot be empty');
    }

    /**
     * Create exception for invalid character
     */
    public static function invalidCharacter(string $name, string $char): self
    {
        return new self(sprintf(
            'Cookie name "%s" contains invalid character: %s',
            $name,
            $char === ' ' ? '(space)' : $char
        ));
    }

    /**
     * Create exception for cookie prefix constraint violation
     *
     * @param string $name Cookie name with prefix
     * @param string $prefix The prefix (__Host- or __Secure-)
     * @param string $constraint The constraint that was violated
     */
    public static function prefixConstraintViolation(string $name, string $prefix, string $constraint): self
    {
        return new self(sprintf(
            'Cookie "%s" uses %s prefix but violates constraint: %s',
            $name,
            $prefix,
            $constraint
        ));
    }
}
