<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Totp;

use Random\RandomException;
use SensitiveParameter;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\Totp\Encoding\Base32;
use Zappzarapp\Security\Totp\Exception\InvalidBase32Exception;
use Zappzarapp\Security\Totp\Exception\InvalidTotpSecretException;

/**
 * Shared secret for HOTP/TOTP code generation
 *
 * Wraps at least 20 bytes (160 bit, the RFC 4226 minimum) of key
 * material in a SecretValue, inheriting its leak resistance: redacted
 * debug output, redacted JSON serialization, serialize() protection,
 * and sodium_memzero() on destruction.
 *
 * ## Usage
 *
 * ```php
 * // Enrollment: generate and show/provision once
 * $secret = TotpSecret::generate();
 * $encoded = $secret->toBase32(); // store encrypted, show as QR via ProvisioningUri
 *
 * // Verification: load it back
 * $secret = TotpSecret::fromBase32($encoded);
 * ```
 */
final readonly class TotpSecret
{
    /**
     * RFC 4226 minimum secret length (160 bit)
     */
    public const int MINIMUM_BYTES = 20;

    private SecretValue $material;

    /**
     * @param string $bytes At least 20 bytes of raw secret material
     *
     * @throws InvalidTotpSecretException If the secret is shorter than 160 bit
     */
    public function __construct(
        #[SensitiveParameter]
        string $bytes,
    ) {
        if (strlen($bytes) < self::MINIMUM_BYTES) {
            throw InvalidTotpSecretException::tooShort(self::MINIMUM_BYTES, strlen($bytes));
        }

        $this->material = new SecretValue($bytes);
    }

    /**
     * Generate a new random secret sized for the given algorithm
     *
     * The length matches the hash output size as recommended by RFC 6238
     * (SHA-1: 20 bytes, SHA-256: 32 bytes, SHA-512: 64 bytes).
     *
     * @throws RandomException If no secure randomness source is available
     */
    public static function generate(TotpAlgorithm $algorithm = TotpAlgorithm::Sha1): self
    {
        return new self(random_bytes($algorithm->recommendedSecretBytes()));
    }

    /**
     * Create from the base32 form used in otpauth:// provisioning
     *
     * @throws InvalidBase32Exception If the encoding is not strict RFC 4648 base32
     * @throws InvalidTotpSecretException If the decoded secret is shorter than 160 bit
     */
    public static function fromBase32(
        #[SensitiveParameter]
        string $encoded,
    ): self {
        return new self(Base32::decode($encoded));
    }

    /**
     * Get the unpadded uppercase base32 form for provisioning
     */
    public function toBase32(): string
    {
        return Base32::encode($this->material->reveal());
    }

    /**
     * Get the raw secret material
     *
     * Returns a copy the caller is responsible for - minimize its lifetime.
     */
    public function bytes(): string
    {
        return $this->material->reveal();
    }

    /**
     * Redact the secret in var_dump() and debugger output
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['material' => '***REDACTED***'];
    }
}
