<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption;

use Random\RandomException;
use SensitiveParameter;
use SodiumException;
use Zappzarapp\Security\Encryption\Exception\DecryptionException;
use Zappzarapp\Security\Password\Security\ClearsMemory;

/**
 * Authenticated symmetric encryption with XChaCha20-Poly1305
 *
 * Secure by design:
 *
 * - Single algorithm, no negotiable (and thus downgradeable) cipher choices
 * - XChaCha20's 24-byte random nonce is large enough that nonce reuse is
 *   statistically negligible - no counter state to manage
 * - Authenticated encryption: tampering is detected before any plaintext
 *   is returned
 * - Optional additional data (AAD) binds a ciphertext to its context
 *   (e.g. a user ID or record ID), preventing ciphertext swapping
 *
 * ## Usage
 *
 * ```php
 * $encryptor = new SymmetricEncryptor();
 * $key       = EncryptionKey::generate();
 *
 * $ciphertext = $encryptor->encrypt('sensitive data', $key, additionalData: 'user:42');
 * $stored     = $ciphertext->toString(); // "v1...."
 *
 * $plaintext = $encryptor->decrypt(Ciphertext::fromString($stored), $key, additionalData: 'user:42');
 * ```
 */
final readonly class SymmetricEncryptor
{
    use ClearsMemory;

    /**
     * Encrypt plaintext with a fresh random nonce
     *
     * @param string $plaintext The data to encrypt
     * @param EncryptionKey $key The symmetric key
     * @param string $additionalData Optional context data that must match on decryption
     *
     * @throws RandomException If no secure randomness source is available
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function encrypt(
        #[SensitiveParameter]
        string $plaintext,
        EncryptionKey $key,
        string $additionalData = '',
    ): Ciphertext {
        $nonce    = random_bytes(Ciphertext::NONCE_BYTES);
        $keyBytes = $key->bytes();

        try {
            $payload = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                $additionalData,
                $nonce,
                $keyBytes
            );
        } finally {
            $this->clearMemory($keyBytes);
        }

        return new Ciphertext($nonce, $payload);
    }

    /**
     * Decrypt and authenticate a ciphertext
     *
     * @param Ciphertext $ciphertext The ciphertext to decrypt
     * @param EncryptionKey $key The symmetric key
     * @param string $additionalData Context data that was passed to encrypt()
     *
     * @throws DecryptionException If authentication fails (wrong key, tampering, or AAD mismatch)
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function decrypt(
        Ciphertext $ciphertext,
        EncryptionKey $key,
        string $additionalData = '',
    ): string {
        $keyBytes = $key->bytes();

        try {
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext->payload,
                $additionalData,
                $ciphertext->nonce,
                $keyBytes
            );
        } finally {
            $this->clearMemory($keyBytes);
        }

        if ($plaintext === false) {
            throw DecryptionException::failed();
        }

        return $plaintext;
    }
}
