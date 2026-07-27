<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption;

use Zappzarapp\Security\Encryption\Exception\InvalidCiphertextException;

/**
 * Authenticated ciphertext produced by SymmetricEncryptor
 *
 * Holds the random nonce and the encrypted payload (including the
 * Poly1305 authentication tag). The transportable string form is
 * versioned: "v1." followed by base64(nonce || payload).
 *
 * Ciphertext is not secret - this value object is safe to log, store,
 * and serialize.
 */
final readonly class Ciphertext
{
    /**
     * Format prefix of the current string representation
     */
    public const string FORMAT_PREFIX = 'v1.';

    /**
     * Nonce length for XChaCha20-Poly1305
     */
    public const int NONCE_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    /**
     * Length of the Poly1305 authentication tag
     */
    public const int TAG_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;

    /**
     * @param string $nonce The 24-byte nonce used for encryption
     * @param string $payload The encrypted bytes including the authentication tag
     *
     * @throws InvalidCiphertextException If nonce or payload have invalid lengths
     */
    public function __construct(
        public string $nonce,
        public string $payload,
    ) {
        if (strlen($this->nonce) !== self::NONCE_BYTES) {
            throw InvalidCiphertextException::truncated(
                self::NONCE_BYTES,
                strlen($this->nonce)
            );
        }

        if (strlen($this->payload) < self::TAG_BYTES) {
            throw InvalidCiphertextException::truncated(
                self::TAG_BYTES,
                strlen($this->payload)
            );
        }
    }

    /**
     * Parse the versioned string form produced by toString()
     *
     * @throws InvalidCiphertextException If the format, encoding, or length is invalid
     */
    public static function fromString(string $encoded): self
    {
        if (!str_starts_with($encoded, self::FORMAT_PREFIX)) {
            throw InvalidCiphertextException::unsupportedFormat(self::FORMAT_PREFIX);
        }

        $binary = base64_decode(substr($encoded, strlen(self::FORMAT_PREFIX)), true);

        if ($binary === false) {
            throw InvalidCiphertextException::invalidEncoding();
        }

        if (strlen($binary) < self::NONCE_BYTES + self::TAG_BYTES) {
            throw InvalidCiphertextException::truncated(
                self::NONCE_BYTES + self::TAG_BYTES,
                strlen($binary)
            );
        }

        return new self(
            substr($binary, 0, self::NONCE_BYTES),
            substr($binary, self::NONCE_BYTES)
        );
    }

    /**
     * Get the versioned, transportable string form
     */
    public function toString(): string
    {
        return self::FORMAT_PREFIX . base64_encode($this->nonce . $this->payload);
    }

    /**
     * Get the raw binary form (nonce || payload), without version prefix
     */
    public function toBinary(): string
    {
        return $this->nonce . $this->payload;
    }
}
