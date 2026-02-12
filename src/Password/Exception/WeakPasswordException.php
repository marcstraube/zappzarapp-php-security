<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Exception;

use RuntimeException;

/**
 * Exception thrown when a password is too weak
 */
final class WeakPasswordException extends RuntimeException
{
    /**
     * Create for low entropy
     */
    public static function lowEntropy(float $bits, float $required): self
    {
        return new self(sprintf(
            'Password entropy too low: %.1f bits (minimum %.1f bits required)',
            $bits,
            $required
        ));
    }

    /**
     * Create for common password
     */
    public static function commonPassword(): self
    {
        return new self('Password is too common or easily guessable');
    }

    /**
     * Create for pattern-based weakness
     */
    public static function patternDetected(string $pattern): self
    {
        return new self(sprintf('Password contains weak pattern: %s', $pattern));
    }
}
