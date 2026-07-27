<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption;

use Zappzarapp\Security\Encryption\Exception\InvalidCiphertextException;

/**
 * Ciphertext produced by EnvelopeEncryptor
 *
 * Combines the wrapped (encrypted) data key and the encrypted payload.
 * The wrapped key has a fixed size (24-byte nonce + 32-byte key +
 * 16-byte tag = 72 bytes), so the string form needs no delimiter:
 * "e1." followed by base64(wrappedKey || payload).
 */
final readonly class EnvelopeCiphertext
{
    /**
     * Format prefix of the current string representation
     */
    public const string FORMAT_PREFIX = 'e1.';

    /**
     * Fixed binary size of the wrapped data key (nonce + key + tag)
     */
    public const int WRAPPED_KEY_BYTES = Ciphertext::NONCE_BYTES
        + EncryptionKey::LENGTH_BYTES
        + Ciphertext::TAG_BYTES;

    /**
     * @param Ciphertext $wrappedKey The data key, encrypted with the key encryption key
     * @param Ciphertext $payload The data, encrypted with the data key
     *
     * @throws InvalidCiphertextException If the wrapped key has an unexpected size
     */
    public function __construct(
        public Ciphertext $wrappedKey,
        public Ciphertext $payload,
    ) {
        $expectedPayloadBytes = EncryptionKey::LENGTH_BYTES + Ciphertext::TAG_BYTES;

        if (strlen($this->wrappedKey->payload) !== $expectedPayloadBytes) {
            throw InvalidCiphertextException::truncated(
                $expectedPayloadBytes,
                strlen($this->wrappedKey->payload)
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

        $minimumBytes = self::WRAPPED_KEY_BYTES + Ciphertext::NONCE_BYTES + Ciphertext::TAG_BYTES;

        if (strlen($binary) < $minimumBytes) {
            throw InvalidCiphertextException::truncated($minimumBytes, strlen($binary));
        }

        $wrappedKeyBinary = substr($binary, 0, self::WRAPPED_KEY_BYTES);
        $payloadBinary    = substr($binary, self::WRAPPED_KEY_BYTES);

        return new self(
            new Ciphertext(
                substr($wrappedKeyBinary, 0, Ciphertext::NONCE_BYTES),
                substr($wrappedKeyBinary, Ciphertext::NONCE_BYTES)
            ),
            new Ciphertext(
                substr($payloadBinary, 0, Ciphertext::NONCE_BYTES),
                substr($payloadBinary, Ciphertext::NONCE_BYTES)
            )
        );
    }

    /**
     * Get the versioned, transportable string form
     */
    public function toString(): string
    {
        return self::FORMAT_PREFIX . base64_encode(
            $this->wrappedKey->toBinary() . $this->payload->toBinary()
        );
    }
}
