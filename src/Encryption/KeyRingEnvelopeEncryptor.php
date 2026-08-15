<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

/** @noinspection PhpDocRedundantThrowsInspection @throws documents exceptions propagated via KeyRingEncryptor - verified by PHPStan's checked-exception analysis */

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption;

use Random\RandomException;
use SensitiveParameter;
use SodiumException;
use Zappzarapp\Security\Encryption\Exception\DecryptionException;
use Zappzarapp\Security\Encryption\Exception\UnknownKeyVersionException;
use Zappzarapp\Security\Password\Security\ClearsMemory;

/**
 * Envelope encryption against a key ring, enabling cheap KEK rotation
 *
 * Like EnvelopeEncryptor, but the key encryption key comes from a
 * KeyRing and the wrapped data key is stamped with its version. This is
 * where envelope encryption pays off: rewrap() migrates a ciphertext to
 * the active KEK by re-wrapping only the 32-byte data key - the payload
 * bytes are reused untouched, no matter how large they are.
 *
 * Wrapped data keys are domain-separated from general data: their
 * additional data carries a fixed "zzp:dek-wrap\0" label, so a wrapped
 * key can never authenticate as an ordinary v2 ciphertext (and vice
 * versa), even when both encryptors share one ring and one additional
 * data value. That label prefix is reserved - do not start your own
 * additional data with it.
 *
 * ## Usage
 *
 * ```php
 * $envelope = new KeyRingEnvelopeEncryptor($ring);
 *
 * $sealed = $envelope->seal($document, additionalData: 'doc:17');
 * $stored = $sealed->toString(); // "e2.3...."
 *
 * $sealed = VersionedEnvelopeCiphertext::fromString($stored);
 *
 * if ($envelope->needsRotation($sealed)) {
 *     $stored = $envelope->rewrap($sealed, additionalData: 'doc:17')->toString();
 * }
 *
 * $document = $envelope->open($sealed, additionalData: 'doc:17');
 * ```
 */
final readonly class KeyRingEnvelopeEncryptor
{
    use ClearsMemory;

    /**
     * Domain-separation label for wrapped data keys
     *
     * Bound into the additional data of every wrap operation so wrapped
     * keys and general v2 ciphertexts live in distinct AEAD domains.
     */
    private const string WRAP_CONTEXT = "zzp:dek-wrap\0";

    private KeyRingEncryptor $keyEncryptor;

    public function __construct(
        KeyRing $keyRing,
        private SymmetricEncryptor $encryptor = new SymmetricEncryptor(),
    ) {
        $this->keyEncryptor = new KeyRingEncryptor($keyRing, $encryptor);
    }

    /**
     * Encrypt plaintext under a fresh data key, wrapping the data key
     * with the ring's active key
     *
     * @param string $plaintext The data to encrypt
     * @param string $additionalData Optional context data that must match on open()
     *
     * @throws RandomException If no secure randomness source is available
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function seal(
        #[SensitiveParameter]
        string $plaintext,
        string $additionalData = '',
    ): VersionedEnvelopeCiphertext {
        $dataKey = EncryptionKey::generate();

        return new VersionedEnvelopeCiphertext(
            $this->keyEncryptor->encrypt($dataKey->bytes(), self::WRAP_CONTEXT . $additionalData),
            $this->encryptor->encrypt($plaintext, $dataKey, $additionalData)
        );
    }

    /**
     * Unwrap the data key with the matching ring key and decrypt the payload
     *
     * @param VersionedEnvelopeCiphertext $envelope The envelope to open
     * @param string $additionalData Context data that was passed to seal()
     *
     * @throws UnknownKeyVersionException If the referenced key is not in the ring
     * @throws DecryptionException If authentication of the wrapped key or payload fails
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function open(
        VersionedEnvelopeCiphertext $envelope,
        string $additionalData = '',
    ): string {
        $dataKey = new EncryptionKey(
            $this->keyEncryptor->decrypt($envelope->wrappedKey, self::WRAP_CONTEXT . $additionalData)
        );

        return $this->encryptor->decrypt($envelope->payload, $dataKey, $additionalData);
    }

    /**
     * Open a version-less 1.3.0 envelope with the ring's oldest key
     *
     * Migration path for envelopes produced by EnvelopeEncryptor before
     * key rotation existed: the pre-ring key must be provisioned as the
     * lowest version in the ring.
     *
     * @param EnvelopeCiphertext $envelope The version-less envelope to open
     * @param string $additionalData Context data that was passed to seal()
     *
     * @throws DecryptionException If authentication of the wrapped key or payload fails
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function openLegacy(
        EnvelopeCiphertext $envelope,
        string $additionalData = '',
    ): string {
        $dataKey = new EncryptionKey(
            $this->keyEncryptor->decryptLegacy($envelope->wrappedKey, $additionalData)
        );

        return $this->encryptor->decrypt($envelope->payload, $dataKey, $additionalData);
    }

    /**
     * Check whether the data key is wrapped under an outdated ring key
     */
    public function needsRotation(VersionedEnvelopeCiphertext $envelope): bool
    {
        return $this->keyEncryptor->needsRotation($envelope->wrappedKey);
    }

    /**
     * Re-wrap the data key with the ring's active key, reusing the payload
     *
     * Returns the envelope unchanged if it already uses the active key.
     * The payload is never decrypted - only the 32-byte data key is
     * unwrapped and wrapped again.
     *
     * @param VersionedEnvelopeCiphertext $envelope The envelope to migrate
     * @param string $additionalData Context data that was passed to seal()
     *
     * @throws UnknownKeyVersionException If the referenced key is not in the ring
     * @throws DecryptionException If authentication of the wrapped key fails
     * @throws RandomException If no secure randomness source is available
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function rewrap(
        VersionedEnvelopeCiphertext $envelope,
        string $additionalData = '',
    ): VersionedEnvelopeCiphertext {
        if (!$this->needsRotation($envelope)) {
            return $envelope;
        }

        $dataKeyBytes = $this->keyEncryptor->decrypt(
            $envelope->wrappedKey,
            self::WRAP_CONTEXT . $additionalData
        );

        try {
            return new VersionedEnvelopeCiphertext(
                $this->keyEncryptor->encrypt($dataKeyBytes, self::WRAP_CONTEXT . $additionalData),
                $envelope->payload
            );
        } finally {
            $this->clearMemory($dataKeyBytes);
        }
    }

    /**
     * Re-wrap a version-less 1.3.0 envelope with the ring's active key
     *
     * @param EnvelopeCiphertext $envelope The version-less envelope to migrate
     * @param string $additionalData Context data that was passed to seal()
     *
     * @throws DecryptionException If authentication of the wrapped key fails
     * @throws RandomException If no secure randomness source is available
     * @throws SodiumException If the underlying sodium operation fails
     */
    public function rewrapLegacy(
        EnvelopeCiphertext $envelope,
        string $additionalData = '',
    ): VersionedEnvelopeCiphertext {
        $dataKeyBytes = $this->keyEncryptor->decryptLegacy($envelope->wrappedKey, $additionalData);

        try {
            return new VersionedEnvelopeCiphertext(
                $this->keyEncryptor->encrypt($dataKeyBytes, self::WRAP_CONTEXT . $additionalData),
                $envelope->payload
            );
        } finally {
            $this->clearMemory($dataKeyBytes);
        }
    }
}
