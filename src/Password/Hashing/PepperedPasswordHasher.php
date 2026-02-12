<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Hashing;

use InvalidArgumentException;
use Override;
use RuntimeException;
use SensitiveParameter;
use Zappzarapp\Security\Password\Security\ClearsMemory;

/**
 * Password hasher with pepper support
 *
 * A pepper is a secret key that's combined with passwords before hashing.
 * This provides defense-in-depth: even if the password hashes are stolen,
 * attackers still need the pepper to perform offline attacks.
 *
 * Uses HKDF (RFC 5869) for cryptographically correct key derivation.
 *
 * ## Security Considerations
 *
 * - The pepper should be stored separately from the database (e.g., in environment)
 * - Use a cryptographically random pepper of at least 32 bytes
 * - Never log or expose the pepper
 * - Rotating peppers is complex - plan for key management
 *
 * ## Basic Usage
 *
 * ```php
 * $pepper = getenv('PASSWORD_PEPPER');
 * $hasher = new PepperedPasswordHasher($pepper);
 *
 * $hash = $hasher->hash('MySecureP@ssword');
 * $valid = $hasher->verify('MySecureP@ssword', $hash);
 * ```
 *
 * ## With Custom Base Hasher
 *
 * ```php
 * $hasher = new PepperedPasswordHasher(
 *     pepper: $pepper,
 *     baseHasher: DefaultPasswordHasher::highSecurity()
 * );
 * ```
 */
final readonly class PepperedPasswordHasher implements PasswordHasher
{
    use ClearsMemory;

    /**
     * Minimum pepper length in bytes (OWASP recommendation)
     */
    private const int MIN_PEPPER_LENGTH = 32;

    /**
     * @param string $pepper Secret pepper key (min 32 bytes, use random_bytes(32))
     * @param PasswordHasher $baseHasher The underlying hasher to use
     *
     * @throws InvalidArgumentException If pepper is shorter than 32 bytes
     */
    public function __construct(
        #[SensitiveParameter] private string $pepper,
        private PasswordHasher $baseHasher = new DefaultPasswordHasher()
    ) {
        if (strlen($pepper) < self::MIN_PEPPER_LENGTH) {
            throw new InvalidArgumentException(
                sprintf('Pepper must be at least %d bytes, got %d', self::MIN_PEPPER_LENGTH, strlen($pepper))
            );
        }
    }

    #[Override]
    public function hash(#[SensitiveParameter] string $password): string
    {
        $peppered = $this->applyPepper($password);

        try {
            return $this->baseHasher->hash($peppered);
        } finally {
            $this->clearMemory($peppered);
        }
    }

    #[Override]
    public function verify(#[SensitiveParameter] string $password, string $hash): bool
    {
        $peppered = $this->applyPepper($password);

        try {
            return $this->baseHasher->verify($peppered, $hash);
        } finally {
            $this->clearMemory($peppered);
        }
    }

    #[Override]
    public function needsRehash(string $hash): bool
    {
        return $this->baseHasher->needsRehash($hash);
    }

    /**
     * Apply pepper to password using HKDF
     *
     * HKDF (Hash-based Key Derivation Function) is the correct primitive for
     * deriving keys from input keying material. It provides:
     * - Extract: Concentrates entropy from the password
     * - Expand: Derives a fixed-length key suitable for Argon2/bcrypt
     *
     * Using HKDF instead of HMAC is more semantically correct for key derivation.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc5869
     */
    private function applyPepper(#[SensitiveParameter] string $password): string
    {
        // HKDF requires non-empty IKM. For empty passwords, use a null byte
        // as a placeholder to maintain compatibility while still being secure
        // (the pepper still provides entropy for the derivation).
        $ikm = $password !== '' ? $password : "\x00";

        // Use HKDF-SHA256 to derive a key from password and pepper
        // - IKM (Input Keying Material): password (or placeholder)
        // - Salt: pepper (used in extract phase)
        // - Info: context string for domain separation
        // - Length: 32 bytes (256 bits) for bcrypt/Argon2 compatibility
        $derived = hash_hkdf('sha256', $ikm, 32, 'zappzarapp-password-pepper', $this->pepper);

        if (strlen($derived) !== 32) {
            throw new RuntimeException('HKDF must produce exactly 32 bytes');
        }

        return $derived;
    }

    /**
     * Create with default Argon2id hasher
     */
    public static function argon2id(#[SensitiveParameter] string $pepper): self
    {
        return new self($pepper, DefaultPasswordHasher::argon2id());
    }

    /**
     * Create with high security settings
     */
    public static function highSecurity(#[SensitiveParameter] string $pepper): self
    {
        return new self($pepper, DefaultPasswordHasher::highSecurity());
    }
}
