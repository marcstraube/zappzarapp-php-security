<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption;

use Zappzarapp\Security\Encryption\Exception\InvalidCiphertextException;

/**
 * Envelope ciphertext produced by KeyRingEnvelopeEncryptor
 *
 * Combines a versioned wrapped data key (encrypted under a key-ring key)
 * and the encrypted payload. Only the wrapped key carries a version: the
 * payload is encrypted with the per-message data key and survives KEK
 * rotation untouched.
 *
 * The wrapped key has a fixed size (24-byte nonce + 32-byte key +
 * 16-byte tag = 72 bytes), so the string form needs no delimiter:
 * "e2.<version>." followed by base64(wrappedKey || payload).
 */
final readonly class VersionedEnvelopeCiphertext
{
    /**
     * Format prefix of the current string representation
     */
    public const string FORMAT_PREFIX = 'e2.';

    /**
     * @param VersionedCiphertext $wrappedKey The data key, encrypted with a key-ring key
     * @param Ciphertext $payload The data, encrypted with the data key
     *
     * @throws InvalidCiphertextException If the wrapped key has an unexpected size
     */
    public function __construct(
        public VersionedCiphertext $wrappedKey,
        public Ciphertext $payload,
    ) {
        $expectedPayloadBytes = EncryptionKey::LENGTH_BYTES + Ciphertext::TAG_BYTES;

        if (strlen($this->wrappedKey->ciphertext->payload) !== $expectedPayloadBytes) {
            throw InvalidCiphertextException::truncated(
                $expectedPayloadBytes,
                strlen($this->wrappedKey->ciphertext->payload)
            );
        }
    }

    /**
     * Get the version of the key-ring key the data key is wrapped under
     */
    public function keyVersion(): int
    {
        return $this->wrappedKey->keyVersion;
    }

    /**
     * Parse the versioned string form produced by toString()
     *
     * @throws InvalidCiphertextException If the format, version, encoding, or length is invalid
     */
    public static function fromString(string $encoded): self
    {
        if (!str_starts_with($encoded, self::FORMAT_PREFIX)) {
            throw InvalidCiphertextException::unsupportedFormat(self::FORMAT_PREFIX);
        }

        $versioned = VersionedCiphertext::fromString(
            VersionedCiphertext::FORMAT_PREFIX . substr($encoded, strlen(self::FORMAT_PREFIX))
        );

        $envelope = EnvelopeCiphertext::fromBinary($versioned->ciphertext->toBinary());

        return new self(
            new VersionedCiphertext($versioned->keyVersion, $envelope->wrappedKey),
            $envelope->payload
        );
    }

    /**
     * Get the versioned, transportable string form
     */
    public function toString(): string
    {
        return self::FORMAT_PREFIX
            . $this->wrappedKey->keyVersion
            . '.'
            . base64_encode($this->wrappedKey->ciphertext->toBinary() . $this->payload->toBinary());
    }
}
