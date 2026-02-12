<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive
 * @noinspection PhpComposerExtensionStubsInspection ext-memcached is optional (suggest), class only used when available
 */

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Storage;

use Memcached;
use Override;

/**
 * Memcached-based rate limit storage
 *
 * Uses atomic increment with add() fallback for race condition handling.
 * For distributed environments.
 *
 * @psalm-suppress UndefinedClass (Memcached extension not always installed)
 * @psalm-suppress MixedReturnTypeCoercion
 * @psalm-suppress MixedReturnStatement
 * @psalm-suppress MixedAssignment
 */
final readonly class MemcachedStorage implements RateLimitStorage
{
    public function __construct(
        private Memcached $client,
        private string $prefix = 'ratelimit:',
    ) {
    }

    #[Override]
    public function get(string $key): ?array
    {
        $data = $this->client->get($this->prefix . $key);

        return is_array($data) ? $data : null;
    }

    #[Override]
    public function set(string $key, array $data, int $ttl): void
    {
        $this->client->set($this->prefix . $key, $data, $ttl);
    }

    #[Override]
    public function delete(string $key): void
    {
        $this->client->delete($this->prefix . $key);
    }

    #[Override]
    public function increment(string $key, int $amount, int $ttl): int
    {
        $prefixedKey = $this->prefix . $key;

        // Try to increment existing key
        /** @var int|false $result */
        $result = $this->client->increment($prefixedKey, $amount);

        if ($result !== false) {
            return $result;
        }

        // Key doesn't exist - try to add it atomically
        // add() only succeeds if key doesn't exist (race condition safe)
        if ($this->client->add($prefixedKey, $amount, $ttl)) {
            return $amount;
        }

        // Another process created the key, try increment again
        /** @var int|false $result */
        $result = $this->client->increment($prefixedKey, $amount);

        return $result !== false ? $result : $amount;
    }
}
