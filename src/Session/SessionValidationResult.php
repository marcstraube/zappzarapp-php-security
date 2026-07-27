<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Session;

/**
 * Result of a session security validation
 *
 * Any non-VALID result should be handled by destroying the session and
 * requiring re-authentication.
 */
enum SessionValidationResult: string
{
    /**
     * Session passed all security checks
     */
    case VALID = 'valid';

    /**
     * Session has no security metadata (initialize() was never called)
     */
    case UNINITIALIZED = 'uninitialized';

    /**
     * Client fingerprint does not match the one bound at initialization
     */
    case FINGERPRINT_MISMATCH = 'fingerprint_mismatch';

    /**
     * Session exceeded its absolute lifetime
     */
    case ABSOLUTE_TIMEOUT_EXCEEDED = 'absolute_timeout_exceeded';

    /**
     * Session was inactive for longer than the idle timeout
     */
    case IDLE_TIMEOUT_EXCEEDED = 'idle_timeout_exceeded';

    /**
     * Whether the session passed all checks
     */
    public function isValid(): bool
    {
        return $this === self::VALID;
    }

    /**
     * Human-readable description for logging
     */
    public function description(): string
    {
        return match ($this) {
            self::VALID                     => 'Session passed all security checks',
            self::UNINITIALIZED             => 'Session has no security metadata',
            self::FINGERPRINT_MISMATCH      => 'Session client fingerprint mismatch',
            self::ABSOLUTE_TIMEOUT_EXCEEDED => 'Session exceeded its absolute lifetime',
            self::IDLE_TIMEOUT_EXCEEDED     => 'Session idle timeout exceeded',
        };
    }
}
