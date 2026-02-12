<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Hashing;

/**
 * Password hashing algorithms
 */
enum HashAlgorithm: string
{
    /**
     * Argon2id (recommended)
     *
     * Combines Argon2i (side-channel resistance) and Argon2d (GPU resistance).
     * Best choice for password hashing in 2024+.
     */
    case ARGON2ID = 'argon2id';

    /**
     * Argon2i
     *
     * Optimized for side-channel attack resistance.
     * Use when side-channel attacks are a primary concern.
     */
    case ARGON2I = 'argon2i';

    /**
     * bcrypt
     *
     * Widely supported legacy algorithm.
     * Has 72-byte password length limit.
     */
    case BCRYPT = 'bcrypt';

    /**
     * Get the PHP PASSWORD_* constant
     */
    public function constant(): string
    {
        return match ($this) {
            self::ARGON2ID => PASSWORD_ARGON2ID,
            self::ARGON2I  => PASSWORD_ARGON2I,
            self::BCRYPT   => PASSWORD_BCRYPT,
        };
    }

    /**
     * Check if this algorithm has a password length limit
     */
    public function hasLengthLimit(): bool
    {
        return $this === self::BCRYPT;
    }

    /**
     * Get the maximum password length (0 = unlimited)
     */
    public function maxLength(): int
    {
        return match ($this) {
            self::BCRYPT => 72,
            default      => 0,
        };
    }
}
