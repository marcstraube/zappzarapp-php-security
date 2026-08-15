<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption;

use Zappzarapp\Security\Encryption\Exception\InvalidCiphertextException;

/**
 * Ciphertext produced by KeyRingEncryptor, carrying the key version
 *
 * Wraps a regular Ciphertext together with the integer version of the
 * key-ring key it was encrypted under. The transportable string form is
 * "v2.<version>." followed by base64(nonce || payload).
 *
 * The version is parsed strictly: a positive integer without leading
 * zeros, at most 9 digits (no user-controlled strings, no overflow).
 * Note that the version header is not merely informational - the
 * encrypting side binds it into the additional data, so a re-stamped
 * header fails authentication (see KeyRingEncryptor).
 *
 * Ciphertext is not secret - this value object is safe to log, store,
 * and serialize.
 */
final readonly class VersionedCiphertext
{
    /**
     * Format prefix of the current string representation
     */
    public const string FORMAT_PREFIX = 'v2.';

    /**
     * Largest supported key version (9 decimal digits)
     */
    public const int MAX_KEY_VERSION = 999_999_999;

    /**
     * @param int $keyVersion Version of the key-ring key used for encryption
     * @param Ciphertext $ciphertext The encrypted data
     *
     * @throws InvalidCiphertextException If the key version is out of range
     */
    public function __construct(
        public int $keyVersion,
        public Ciphertext $ciphertext,
    ) {
        if ($this->keyVersion < 1 || $this->keyVersion > self::MAX_KEY_VERSION) {
            throw InvalidCiphertextException::invalidKeyVersion();
        }
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

        $rest      = substr($encoded, strlen(self::FORMAT_PREFIX));
        $separator = strpos($rest, '.');

        if ($separator === false) {
            throw InvalidCiphertextException::invalidKeyVersion();
        }

        $digits = substr($rest, 0, $separator);

        if (preg_match('/^[1-9]\d{0,8}$/', $digits) !== 1) {
            throw InvalidCiphertextException::invalidKeyVersion();
        }

        $binary = base64_decode(substr($rest, $separator + 1), true);

        if ($binary === false) {
            throw InvalidCiphertextException::invalidEncoding();
        }

        return new self((int) $digits, Ciphertext::fromBinary($binary));
    }

    /**
     * Get the versioned, transportable string form
     */
    public function toString(): string
    {
        return self::FORMAT_PREFIX
            . $this->keyVersion
            . '.'
            . base64_encode($this->ciphertext->toBinary());
    }
}
