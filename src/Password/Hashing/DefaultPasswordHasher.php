<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Hashing;

use Override;
use SensitiveParameter;
use Zappzarapp\Security\Password\Security\ClearsMemory;

/**
 * Default password hasher using PHP's password_* functions
 *
 * ## Basic Usage
 *
 * ```php
 * $hasher = new DefaultPasswordHasher();
 *
 * // Hash a password
 * $hash = $hasher->hash('MySecureP@ssword');
 *
 * // Verify a password
 * if ($hasher->verify('MySecureP@ssword', $hash)) {
 *     // Password is correct
 * }
 *
 * // Check if hash needs updating (after config change)
 * if ($hasher->needsRehash($hash)) {
 *     $newHash = $hasher->hash($password);
 *     // Update stored hash
 * }
 * ```
 *
 * ## bcrypt Pre-Hashing
 *
 * When using bcrypt, passwords are automatically pre-hashed with SHA-384
 * to prevent the 72-byte truncation issue. This follows the Dropbox pattern
 * and is transparent to users - no special handling required.
 *
 * @see https://blog.ircmaxell.com/2015/03/security-issue-combining-bcrypt-with.html
 */
final readonly class DefaultPasswordHasher implements PasswordHasher
{
    use ClearsMemory;

    public function __construct(
        private HashConfig $config = new HashConfig(),
    ) {
    }

    #[Override]
    public function hash(#[SensitiveParameter] string $password): string
    {
        $prepared = $this->preparePassword($password);

        try {
            return $this->withClearedMemory($prepared, fn(string $pwd): string => password_hash(
                $pwd,
                $this->config->algorithm->constant(),
                $this->config->toOptions()
            ));
        } finally {
            $this->clearMemory($prepared);
        }
    }

    #[Override]
    public function verify(#[SensitiveParameter] string $password, string $hash): bool
    {
        $prepared = $this->preparePassword($password);

        try {
            return $this->withClearedMemory($prepared, fn(string $pwd): bool => password_verify($pwd, $hash));
        } finally {
            $this->clearMemory($prepared);
        }
    }

    /**
     * Prepare password for hashing
     *
     * For bcrypt, applies SHA-384 pre-hashing to prevent 72-byte truncation.
     * This is the "Dropbox pattern" - a well-established best practice.
     *
     * Using SHA-384 (instead of SHA-256) because:
     * - 48-byte output fits within bcrypt's 72-byte limit
     * - Base64 encoding of 48 bytes = 64 characters (still under 72)
     * - Higher security margin than SHA-256
     *
     * @see https://blog.ircmaxell.com/2015/03/security-issue-combining-bcrypt-with.html
     */
    private function preparePassword(#[SensitiveParameter] string $password): string
    {
        if ($this->config->algorithm !== HashAlgorithm::BCRYPT) {
            return $password;
        }

        // Pre-hash with SHA-384, then base64 encode
        // SHA-384 produces 48 bytes, base64 encodes to 64 chars (< 72 byte limit)
        return base64_encode(hash('sha384', $password, true));
    }

    #[Override]
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash(
            $hash,
            $this->config->algorithm->constant(),
            $this->config->toOptions()
        );
    }

    /**
     * Get password info from hash
     *
     * @return array{algo: string|int|null, algoName: string, options: array<string, mixed>}
     */
    public function getInfo(string $hash): array
    {
        /** @var array{algo: string|int|null, algoName: string, options: array<string, mixed>} */
        return password_get_info($hash);
    }

    /**
     * Create with Argon2id (recommended)
     */
    public static function argon2id(): self
    {
        return new self(HashConfig::argon2id());
    }

    /**
     * Create with bcrypt
     */
    public static function bcrypt(int $cost = HashConfig::DEFAULT_BCRYPT_COST): self
    {
        return new self(HashConfig::bcrypt($cost));
    }

    /**
     * Create with high security settings
     */
    public static function highSecurity(): self
    {
        return new self(HashConfig::highSecurity());
    }
}
