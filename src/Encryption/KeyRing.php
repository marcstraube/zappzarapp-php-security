<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption;

use Zappzarapp\Security\Encryption\Exception\InvalidKeyRingException;
use Zappzarapp\Security\Encryption\Exception\UnknownKeyVersionException;

/**
 * Immutable set of versioned encryption keys with one active key
 *
 * The active key is used for all new encryptions; every key in the ring
 * remains available for decryption. Rotation adds a new key under the
 * next version and makes it active - old ciphertexts stay readable and
 * can be migrated lazily via KeyRingEncryptor::rotate().
 *
 * Retiring a key (withoutKey()) is the explicit, final step of a
 * rotation: ciphertexts still referencing it fail with
 * UnknownKeyVersionException instead of silently falling back.
 *
 * ## Usage
 *
 * ```php
 * // Initial provisioning
 * $ring = KeyRing::create(EncryptionKey::generate());
 *
 * // Rotation: new active key, old key stays readable
 * $ring = $ring->withRotatedKey(EncryptionKey::generate());
 *
 * // Loading from configuration
 * $ring = KeyRing::fromKeys([
 *     1 => EncryptionKey::fromBase64($old),
 *     2 => EncryptionKey::fromBase64($new),
 * ], activeVersion: 2);
 * ```
 */
final readonly class KeyRing
{
    /**
     * @param non-empty-array<int, EncryptionKey> $keys Keys indexed by version
     * @param int $activeVersion Version used for new encryptions
     * @param int $nextVersion Version the next rotation will use; never reused
     *                         even after the highest key was retired
     */
    private function __construct(
        private array $keys,
        public int $activeVersion,
        private int $nextVersion,
    ) {
    }

    /**
     * Create a ring with a single key under version 1
     */
    public static function create(EncryptionKey $key): self
    {
        return new self([1 => $key], 1, 2);
    }

    /**
     * Create a ring from versioned keys
     *
     * @param array<int, EncryptionKey> $keys Keys indexed by version
     * @param int $activeVersion Version used for new encryptions
     *
     * @throws InvalidKeyRingException If the ring is empty, a version is out of range, or the active version is missing
     */
    public static function fromKeys(array $keys, int $activeVersion): self
    {
        if ($keys === []) {
            throw InvalidKeyRingException::empty();
        }

        foreach (array_keys($keys) as $version) {
            if ($version < 1 || $version > VersionedCiphertext::MAX_KEY_VERSION) {
                throw InvalidKeyRingException::invalidVersion(
                    $version,
                    VersionedCiphertext::MAX_KEY_VERSION
                );
            }
        }

        if (!isset($keys[$activeVersion])) {
            throw InvalidKeyRingException::unknownActiveVersion($activeVersion);
        }

        return new self($keys, $activeVersion, max(array_keys($keys)) + 1);
    }

    /**
     * Add a new key under the next version and make it active
     *
     * Version numbers are never reused: retiring the highest key does not
     * free its number, so ciphertexts under a retired version keep failing
     * with UnknownKeyVersionException instead of hitting an unrelated key.
     *
     * @throws InvalidKeyRingException If the next version would exceed the supported range
     */
    public function withRotatedKey(EncryptionKey $key): self
    {
        if ($this->nextVersion > VersionedCiphertext::MAX_KEY_VERSION) {
            throw InvalidKeyRingException::invalidVersion(
                $this->nextVersion,
                VersionedCiphertext::MAX_KEY_VERSION
            );
        }

        $keys                     = $this->keys;
        $keys[$this->nextVersion] = $key;

        return new self($keys, $this->nextVersion, $this->nextVersion + 1);
    }

    /**
     * Retire a key: ciphertexts under this version become undecryptable
     *
     * @throws InvalidKeyRingException If the version is the active key
     * @throws UnknownKeyVersionException If the version is not in the ring
     */
    public function withoutKey(int $version): self
    {
        if ($version === $this->activeVersion) {
            throw InvalidKeyRingException::cannotRemoveActiveKey($version);
        }

        if (!isset($this->keys[$version])) {
            throw UnknownKeyVersionException::forVersion($version);
        }

        $keys = [$this->activeVersion => $this->activeKey()];

        foreach ($this->keys as $existingVersion => $key) {
            if ($existingVersion === $version) {
                continue;
            }

            if ($existingVersion === $this->activeVersion) {
                continue;
            }

            $keys[$existingVersion] = $key;
        }

        return new self($keys, $this->activeVersion, $this->nextVersion);
    }

    /**
     * Get the key used for new encryptions
     */
    public function activeKey(): EncryptionKey
    {
        return $this->keys[$this->activeVersion];
    }

    /**
     * Get the key for a specific version
     *
     * @throws UnknownKeyVersionException If the version is not in the ring
     */
    public function key(int $version): EncryptionKey
    {
        if (!isset($this->keys[$version])) {
            throw UnknownKeyVersionException::forVersion($version);
        }

        return $this->keys[$version];
    }

    /**
     * Check whether a key exists for the given version
     */
    public function has(int $version): bool
    {
        return isset($this->keys[$version]);
    }

    /**
     * Get the lowest version in the ring (used for 1.3.0 legacy ciphertexts)
     */
    public function oldestVersion(): int
    {
        return min(array_keys($this->keys));
    }

    /**
     * Get all versions in the ring, sorted ascending
     *
     * @return list<int>
     */
    public function versions(): array
    {
        $versions = array_keys($this->keys);
        sort($versions);

        return $versions;
    }
}
