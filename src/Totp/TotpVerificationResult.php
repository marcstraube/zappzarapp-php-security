<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp;

/**
 * Result of a TOTP code verification
 *
 * On success, matchedTimeStep identifies the time step the code was
 * accepted for. Persist it and pass it back as $lastAcceptedTimeStep on
 * the next verification - that is what makes each code one-time and
 * blocks replay within the verification window.
 */
final readonly class TotpVerificationResult
{
    private function __construct(
        public bool $valid,
        public ?int $matchedTimeStep,
    ) {
    }

    /**
     * Create for an accepted code
     */
    public static function valid(int $matchedTimeStep): self
    {
        return new self(true, $matchedTimeStep);
    }

    /**
     * Create for a rejected code
     */
    public static function invalid(): self
    {
        return new self(false, null);
    }
}
