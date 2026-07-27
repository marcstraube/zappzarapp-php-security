<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption;

use SensitiveParameter;
use Zappzarapp\Security\Encryption\Exception\InvalidKeyException;
use Zappzarapp\Security\Secrets\SecretValue;

/**
 * Symmetric encryption key for XChaCha20-Poly1305
 *
 * Wraps exactly 32 bytes of key material in a SecretValue, inheriting its
 * leak resistance: redacted debug output, redacted JSON serialization,
 * serialize() protection, and sodium_memzero() on destruction.
 *
 * ## Usage
 *
 * ```php
 * // Generate a new key and store it base64-encoded
 * $key = EncryptionKey::generate();
 * file_put_contents('/run/secrets/app_key', $key->toBase64());
 *
 * // Load it back via the Secrets module
 * $key = EncryptionKey::fromSecretValue(SecretLoader::docker()->load('app_key'));
 * ```
 */
final readonly class EncryptionKey
{
    /**
     * Required key length for XChaCha20-Poly1305
     */
    public const int LENGTH_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

    private SecretValue $material;

    /**
     * @param string $bytes Exactly 32 bytes of raw key material
     *
     * @throws InvalidKeyException If the key material has the wrong length
     */
    public function __construct(
        #[SensitiveParameter]
        string $bytes,
    ) {
        if (strlen($bytes) !== self::LENGTH_BYTES) {
            throw InvalidKeyException::invalidLength(self::LENGTH_BYTES, strlen($bytes));
        }

        $this->material = new SecretValue($bytes);
    }

    /**
     * Generate a new random key
     */
    public static function generate(): self
    {
        return new self(sodium_crypto_aead_xchacha20poly1305_ietf_keygen());
    }

    /**
     * Create from base64-encoded key material
     *
     * @throws InvalidKeyException If the encoding or length is invalid
     */
    public static function fromBase64(
        #[SensitiveParameter]
        string $encoded,
    ): self {
        $bytes = base64_decode($encoded, true);

        if ($bytes === false) {
            throw InvalidKeyException::invalidEncoding();
        }

        return new self($bytes);
    }

    /**
     * Create from a secret loaded via the Secrets module
     *
     * The secret is expected to contain the base64-encoded key, as produced
     * by toBase64() - raw key bytes do not survive the secret file
     * convention (trailing newline trimming).
     *
     * @throws InvalidKeyException If the encoding or length is invalid
     */
    public static function fromSecretValue(SecretValue $secret): self
    {
        return self::fromBase64($secret->reveal());
    }

    /**
     * Get the base64-encoded key material for storage or provisioning
     */
    public function toBase64(): string
    {
        return base64_encode($this->material->reveal());
    }

    /**
     * Get the raw key material
     *
     * Returns a copy the caller is responsible for - minimize its lifetime.
     */
    public function bytes(): string
    {
        return $this->material->reveal();
    }

    /**
     * Redact the key in var_dump() and debugger output
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['material' => '***REDACTED***'];
    }
}
