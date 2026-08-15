<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when TOTP configuration values are out of range
 */
final class InvalidTotpConfigException extends InvalidArgumentException
{
    /**
     * Create for a code length outside the RFC 4226 range
     */
    public static function invalidDigits(int $digits): self
    {
        return new self(sprintf('TOTP digits must be between 6 and 8, got %d', $digits));
    }

    /**
     * Create for a time-step period outside the supported range
     */
    public static function invalidPeriod(int $period): self
    {
        return new self(sprintf('TOTP period must be between 15 and 300 seconds, got %d', $period));
    }

    /**
     * Create for a verification window outside the supported range
     */
    public static function invalidWindow(int $window): self
    {
        return new self(sprintf('TOTP verification window must be between 0 and 10 steps, got %d', $window));
    }

    /**
     * Create for a negative Unix timestamp
     */
    public static function invalidTimestamp(int $timestamp): self
    {
        return new self(sprintf('Timestamp must not be negative, got %d', $timestamp));
    }

    /**
     * Create for a negative HOTP counter
     */
    public static function invalidCounter(int $counter): self
    {
        return new self(sprintf('HOTP counter must not be negative, got %d', $counter));
    }
}
