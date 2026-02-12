<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Strength;

/**
 * Password strength levels
 */
enum StrengthLevel: string
{
    /**
     * Very weak password (< 28 bits entropy)
     *
     * Easily crackable in seconds.
     */
    case VERY_WEAK = 'very_weak';

    /**
     * Weak password (28-35 bits entropy)
     *
     * Can be cracked with moderate resources.
     */
    case WEAK = 'weak';

    /**
     * Fair password (36-59 bits entropy)
     *
     * Provides basic protection but below NIST recommendations.
     */
    case FAIR = 'fair';

    /**
     * Strong password (60-79 bits entropy)
     *
     * Meets NIST SP 800-63B minimum recommendations.
     * Provides good protection for most use cases.
     */
    case STRONG = 'strong';

    /**
     * Very strong password (>= 80 bits entropy)
     *
     * Exceeds NIST recommendations. Provides excellent protection.
     */
    case VERY_STRONG = 'very_strong';

    /**
     * Get numeric score (0-4)
     */
    public function score(): int
    {
        return match ($this) {
            self::VERY_WEAK   => 0,
            self::WEAK        => 1,
            self::FAIR        => 2,
            self::STRONG      => 3,
            self::VERY_STRONG => 4,
        };
    }

    /**
     * Get human-readable label
     */
    public function label(): string
    {
        return match ($this) {
            self::VERY_WEAK   => 'Very Weak',
            self::WEAK        => 'Weak',
            self::FAIR        => 'Fair',
            self::STRONG      => 'Strong',
            self::VERY_STRONG => 'Very Strong',
        };
    }

    /**
     * Check if this level meets a minimum requirement
     */
    public function meetsMinimum(self $minimum): bool
    {
        return $this->score() >= $minimum->score();
    }
}
