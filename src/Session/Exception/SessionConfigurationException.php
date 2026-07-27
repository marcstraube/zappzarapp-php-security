<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Session\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when session security configuration is invalid or
 * cannot be applied
 */
final class SessionConfigurationException extends InvalidArgumentException
{
    /**
     * Create for configuration applied while a session is already active
     */
    public static function sessionAlreadyActive(): self
    {
        return new self(
            'Session configuration must be applied before session_start() - a session is already active'
        );
    }

    /**
     * Create for a timeout that is not a positive number of seconds
     */
    public static function nonPositiveTimeout(string $name, int $value): self
    {
        return new self(sprintf(
            'Session %s timeout must be a positive number of seconds, got %d',
            $name,
            $value
        ));
    }

    /**
     * Create for an idle timeout exceeding the absolute timeout
     */
    public static function idleExceedsAbsolute(int $idleTimeout, int $absoluteTimeout): self
    {
        return new self(sprintf(
            'Session idle timeout (%d) must not exceed the absolute timeout (%d)',
            $idleTimeout,
            $absoluteTimeout
        ));
    }

    /**
     * Create for a session cookie name containing invalid characters
     */
    public static function invalidCookieName(): self
    {
        return new self(
            'Session cookie name contains invalid characters '
            . '(allowed: A-Z, a-z, 0-9, "_", "-", "."; must not be empty)'
        );
    }
}
