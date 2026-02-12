<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Hashing;

use SensitiveParameter;

/**
 * Interface for password hashers
 */
interface PasswordHasher
{
    /**
     * Hash a password
     *
     * @param string $password The plain-text password
     *
     * @return string The hashed password
     */
    public function hash(#[SensitiveParameter] string $password): string;

    /**
     * Verify a password against a hash
     *
     * @param string $password The plain-text password
     * @param string $hash The hash to verify against
     *
     * @return bool True if password matches
     */
    public function verify(#[SensitiveParameter] string $password, string $hash): bool;

    /**
     * Check if a hash needs to be rehashed
     *
     * Use this when updating hashing parameters to migrate old hashes.
     *
     * @param string $hash The hash to check
     *
     * @return bool True if hash should be regenerated
     */
    public function needsRehash(string $hash): bool;
}
