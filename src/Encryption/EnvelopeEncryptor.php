<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption;

use Random\RandomException;
use SensitiveParameter;
use SodiumException;
use Zappzarapp\Security\Encryption\Exception\DecryptionException;

/**
 * Envelope encryption: a fresh data key per message, wrapped by a key
 * encryption key
 *
 * Each seal() call generates a random data encryption key (DEK), encrypts
 * the payload with it, and encrypts the DEK itself with the long-lived key
 * encryption key (KEK). Benefits over direct symmetric encryption:
 *
 * - KEK rotation only requires re-wrapping the small data keys, not
 *   re-encrypting the payloads
 * - The KEK encrypts only 32-byte random keys, never attacker-influenced
 *   plaintext sizes
 * - Compatible with external KMS patterns (the wrapped key can be
 *   re-wrapped by another key holder)
 *
 * The additional data is bound to both the payload and the wrapped key,
 * so neither can be swapped between contexts.
 *
 * ## Usage
 *
 * ```php
 * $envelope = new EnvelopeEncryptor();
 * $kek      = EncryptionKey::fromSecretValue(SecretLoader::docker()->load('app_kek'));
 *
 * $sealed = $envelope->seal($document, $kek, additionalData: 'doc:17');
 * $stored = $sealed->toString(); // "e1..."
 *
 * $document = $envelope->open(EnvelopeCiphertext::fromString($stored), $kek, additionalData: 'doc:17');
 * ```
 */
final readonly class EnvelopeEncryptor
{
    public function __construct(
        private SymmetricEncryptor $encryptor = new SymmetricEncryptor(),
    ) {
    }

    /**
     * Encrypt plaintext under a fresh data key, wrapping the data key
     * with the key encryption key
     *
     * @param string $plaintext The data to encrypt
     * @param EncryptionKey $keyEncryptionKey The long-lived key encryption key
     * @param string $additionalData Optional context data that must match on open()
     *
     * @throws RandomException If no secure randomness source is available
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function seal(
        #[SensitiveParameter]
        string $plaintext,
        EncryptionKey $keyEncryptionKey,
        string $additionalData = '',
    ): EnvelopeCiphertext {
        $dataKey = EncryptionKey::generate();

        $payload    = $this->encryptor->encrypt($plaintext, $dataKey, $additionalData);
        $wrappedKey = $this->encryptor->encrypt($dataKey->bytes(), $keyEncryptionKey, $additionalData);

        return new EnvelopeCiphertext($wrappedKey, $payload);
    }

    /**
     * Unwrap the data key and decrypt the payload
     *
     * @param EnvelopeCiphertext $envelope The envelope to open
     * @param EncryptionKey $keyEncryptionKey The long-lived key encryption key
     * @param string $additionalData Context data that was passed to seal()
     *
     * @throws DecryptionException If authentication of the wrapped key or payload fails
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function open(
        EnvelopeCiphertext $envelope,
        EncryptionKey $keyEncryptionKey,
        string $additionalData = '',
    ): string {
        $dataKey = new EncryptionKey(
            $this->encryptor->decrypt($envelope->wrappedKey, $keyEncryptionKey, $additionalData)
        );

        return $this->encryptor->decrypt($envelope->payload, $dataKey, $additionalData);
    }
}
