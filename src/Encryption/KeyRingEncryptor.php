<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption;

use Random\RandomException;
use SensitiveParameter;
use SodiumException;
use Zappzarapp\Security\Encryption\Exception\DecryptionException;
use Zappzarapp\Security\Encryption\Exception\UnknownKeyVersionException;
use Zappzarapp\Security\Password\Security\ClearsMemory;

/**
 * Symmetric encryption against a key ring, enabling key rotation
 *
 * Encrypts with the ring's active key and stamps the key version into
 * the ciphertext; decryption selects the matching key by version.
 * Rotation is lazy: rotate() re-encrypts a ciphertext under the active
 * key whenever needsRotation() reports it is outdated.
 *
 * The key version is bound into the additional data as a 4-byte
 * big-endian prefix (pack('N', version) . additionalData), so a
 * re-stamped version header fails authentication even if the referenced
 * key exists in the ring.
 *
 * ## Usage
 *
 * ```php
 * $encryptor = new KeyRingEncryptor($ring);
 *
 * $stored = $encryptor->encrypt('sensitive data', additionalData: 'user:42')->toString(); // "v2.3...."
 *
 * $ciphertext = VersionedCiphertext::fromString($stored);
 *
 * if ($encryptor->needsRotation($ciphertext)) {
 *     $stored = $encryptor->rotate($ciphertext, additionalData: 'user:42')->toString();
 * }
 *
 * $plaintext = $encryptor->decrypt($ciphertext, additionalData: 'user:42');
 * ```
 */
final readonly class KeyRingEncryptor
{
    use ClearsMemory;

    public function __construct(
        private KeyRing $keyRing,
        private SymmetricEncryptor $encryptor = new SymmetricEncryptor(),
    ) {
    }

    /**
     * Encrypt plaintext with the ring's active key
     *
     * @param string $plaintext The data to encrypt
     * @param string $additionalData Optional context data that must match on decryption
     *
     * @throws RandomException If no secure randomness source is available
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function encrypt(
        #[SensitiveParameter]
        string $plaintext,
        string $additionalData = '',
    ): VersionedCiphertext {
        $version = $this->keyRing->activeVersion;

        return new VersionedCiphertext(
            $version,
            $this->encryptor->encrypt(
                $plaintext,
                $this->keyRing->activeKey(),
                $this->versionBound($additionalData, $version)
            )
        );
    }

    /**
     * Decrypt a versioned ciphertext with the matching key from the ring
     *
     * @param VersionedCiphertext $ciphertext The ciphertext to decrypt
     * @param string $additionalData Context data that was passed to encrypt()
     *
     * @throws UnknownKeyVersionException If the referenced key is not in the ring
     * @throws DecryptionException If authentication fails (wrong key, tampering, or AAD mismatch)
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function decrypt(
        VersionedCiphertext $ciphertext,
        string $additionalData = '',
    ): string {
        return $this->encryptor->decrypt(
            $ciphertext->ciphertext,
            $this->keyRing->key($ciphertext->keyVersion),
            $this->versionBound($additionalData, $ciphertext->keyVersion)
        );
    }

    /**
     * Decrypt a version-less 1.3.0 ciphertext with the ring's oldest key
     *
     * Migration path for ciphertexts produced by SymmetricEncryptor
     * before key rotation existed: the pre-ring key must be provisioned
     * as the lowest version in the ring.
     *
     * @param Ciphertext $ciphertext The version-less ciphertext to decrypt
     * @param string $additionalData Context data that was passed to encrypt()
     *
     * @throws DecryptionException If authentication fails (wrong key, tampering, or AAD mismatch)
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function decryptLegacy(
        Ciphertext $ciphertext,
        string $additionalData = '',
    ): string {
        return $this->encryptor->decrypt(
            $ciphertext,
            $this->keyRing->key($this->keyRing->oldestVersion()),
            $additionalData
        );
    }

    /**
     * Check whether a ciphertext is encrypted under an outdated key
     */
    public function needsRotation(VersionedCiphertext $ciphertext): bool
    {
        return $ciphertext->keyVersion !== $this->keyRing->activeVersion;
    }

    /**
     * Re-encrypt a ciphertext under the ring's active key
     *
     * Returns the ciphertext unchanged if it already uses the active key.
     *
     * @param VersionedCiphertext $ciphertext The ciphertext to migrate
     * @param string $additionalData Context data that was passed to encrypt()
     *
     * @throws UnknownKeyVersionException If the referenced key is not in the ring
     * @throws DecryptionException If authentication fails (wrong key, tampering, or AAD mismatch)
     * @throws RandomException If no secure randomness source is available
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function rotate(
        VersionedCiphertext $ciphertext,
        string $additionalData = '',
    ): VersionedCiphertext {
        if (!$this->needsRotation($ciphertext)) {
            return $ciphertext;
        }

        $plaintext = $this->decrypt($ciphertext, $additionalData);

        try {
            return $this->encrypt($plaintext, $additionalData);
        } finally {
            $this->clearMemory($plaintext);
        }
    }

    /**
     * Re-encrypt a version-less 1.3.0 ciphertext under the ring's active key
     *
     * @param Ciphertext $ciphertext The version-less ciphertext to migrate
     * @param string $additionalData Context data that was passed to encrypt()
     *
     * @throws DecryptionException If authentication fails (wrong key, tampering, or AAD mismatch)
     * @throws RandomException If no secure randomness source is available
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function rotateLegacy(
        Ciphertext $ciphertext,
        string $additionalData = '',
    ): VersionedCiphertext {
        $plaintext = $this->decryptLegacy($ciphertext, $additionalData);

        try {
            return $this->encrypt($plaintext, $additionalData);
        } finally {
            $this->clearMemory($plaintext);
        }
    }

    /**
     * Bind the key version into the additional data
     *
     * The fixed-width 4-byte prefix is unambiguous: no user-supplied
     * additional data can collide with another version's encoding.
     */
    private function versionBound(string $additionalData, int $version): string
    {
        return pack('N', $version) . $additionalData;
    }
}
