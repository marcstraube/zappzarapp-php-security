<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Exception;

use RuntimeException;

/**
 * Exception thrown when a password is found in data breaches
 */
final class PwnedPasswordException extends RuntimeException
{
    public function __construct(
        private readonly int $occurrences,
    ) {
        parent::__construct(sprintf(
            'Password has been exposed in %d data breach%s',
            $occurrences,
            $occurrences === 1 ? '' : 'es'
        ));
    }

    /**
     * Get the number of breach occurrences
     */
    public function occurrences(): int
    {
        return $this->occurrences;
    }

    /**
     * Create for breached password
     */
    public static function breached(int $occurrences): self
    {
        return new self($occurrences);
    }
}
