<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\SignedUrl;

use Random\RandomException;
use SensitiveParameter;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\SignedUrl\Exception\InvalidSigningKeyException;

/**
 * HMAC-SHA-256 signing key for URL signatures
 *
 * Wraps at least 32 bytes of key material in a SecretValue, inheriting its
 * leak resistance: redacted debug output, redacted JSON serialization,
 * serialize() protection, and sodium_memzero() on destruction.
 *
 * 32 bytes matches the HMAC-SHA-256 output size - shorter keys would
 * reduce the effective security level, longer keys are accepted as-is.
 *
 * ## Usage
 *
 * ```php
 * // Generate a new key and store it base64-encoded
 * $key = SigningKey::generate();
 * file_put_contents('/run/secrets/url_signing_key', $key->toBase64());
 *
 * // Load it back via the Secrets module
 * $key = SigningKey::fromSecretValue(SecretLoader::docker()->load('url_signing_key'));
 * ```
 */
final readonly class SigningKey
{
    /**
     * Minimum key length: the HMAC-SHA-256 output size
     */
    public const int MIN_LENGTH_BYTES = 32;

    private SecretValue $material;

    /**
     * @param string $bytes At least 32 bytes of raw key material
     *
     * @throws InvalidSigningKeyException If the key material is too short
     */
    public function __construct(
        #[SensitiveParameter]
        string $bytes,
    ) {
        if (strlen($bytes) < self::MIN_LENGTH_BYTES) {
            throw InvalidSigningKeyException::tooShort(self::MIN_LENGTH_BYTES, strlen($bytes));
        }

        $this->material = new SecretValue($bytes);
    }

    /**
     * Generate a new random key
     *
     * @throws RandomException If no secure randomness source is available
     */
    public static function generate(): self
    {
        return new self(random_bytes(self::MIN_LENGTH_BYTES));
    }

    /**
     * Create from base64-encoded key material
     *
     * @throws InvalidSigningKeyException If the encoding or length is invalid
     */
    public static function fromBase64(
        #[SensitiveParameter]
        string $encoded,
    ): self {
        $bytes = base64_decode($encoded, true);

        if ($bytes === false) {
            throw InvalidSigningKeyException::invalidEncoding();
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
     * @throws InvalidSigningKeyException If the encoding or length is invalid
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
