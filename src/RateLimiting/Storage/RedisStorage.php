<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Storage;

use JsonException;
use Override;
use Zappzarapp\Security\RateLimiting\Exception\StorageException;

/**
 * Redis-based rate limit storage
 *
 * Supports both phpredis extension (Redis class) and Predis client.
 * For distributed environments with atomic operations.
 *
 * @psalm-suppress MixedReturnTypeCoercion
 * @psalm-suppress MixedReturnStatement
 * @psalm-suppress MixedAssignment
 * @psalm-suppress MixedMethodCall
 */
final readonly class RedisStorage implements RateLimitStorage
{
    /**
     * @param object $client Redis or Predis\Client instance with get/setex/del/incrBy/expire methods
     * @param string $prefix Key prefix for namespacing
     */
    public function __construct(
        private object $client,
        private string $prefix = 'ratelimit:',
    ) {
    }

    #[Override]
    public function get(string $key): ?array
    {
        /** @phpstan-ignore method.notFound (Redis/Predis duck typing) */
        $data = $this->client->get($this->prefix . $key);

        if ($data === false || $data === null) {
            return null;
        }

        $decoded = json_decode((string) $data, true);

        if (!is_array($decoded)) {
            return null;
        }

        return $decoded;
    }

    #[Override]
    public function set(string $key, array $data, int $ttl): void
    {
        try {
            $encoded = json_encode($data, JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw new StorageException('Failed to encode data for storage', 0, $jsonException);
        }

        /** @phpstan-ignore method.notFound (Redis/Predis duck typing) */
        $this->client->setex($this->prefix . $key, $ttl, $encoded);
    }

    #[Override]
    public function delete(string $key): void
    {
        /** @phpstan-ignore method.notFound (Redis/Predis duck typing) */
        $this->client->del($this->prefix . $key);
    }

    #[Override]
    public function increment(string $key, int $amount, int $ttl): int
    {
        $prefixedKey = $this->prefix . $key;

        // Use Lua script for atomic increment with TTL to prevent race conditions.
        // Without this, INCRBY + EXPIRE is not atomic and the key could expire
        // between the two commands, or TTL could be set incorrectly on existing keys.
        $script = <<<'LUA'
            local current = redis.call('INCRBY', KEYS[1], ARGV[1])
            local ttl = redis.call('TTL', KEYS[1])
            if ttl == -1 then
                redis.call('EXPIRE', KEYS[1], ARGV[2])
            end
            return current
        LUA;

        /** @phpstan-ignore method.notFound (Redis/Predis duck typing) */
        return (int) $this->client->eval($script, [$prefixedKey, $amount, $ttl], 1);
    }
}
