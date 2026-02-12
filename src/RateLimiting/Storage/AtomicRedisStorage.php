<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Storage;

use JsonException;
use Override;
use Throwable;
use Zappzarapp\Security\RateLimiting\Exception\StorageException;

/**
 * Atomic Redis-based rate limit storage using Lua scripts
 *
 * Uses Lua scripts for atomic operations to prevent race conditions
 * in distributed environments. All rate limiting operations are
 * executed as single atomic units.
 *
 * ## Usage
 *
 * ```php
 * $redis = new Redis();
 * $redis->connect('localhost');
 * $storage = new AtomicRedisStorage($redis);
 * ```
 *
 * @psalm-suppress MixedReturnTypeCoercion
 * @psalm-suppress MixedReturnStatement
 * @psalm-suppress MixedAssignment
 * @psalm-suppress MixedMethodCall
 * @psalm-suppress MixedArgument
 */
final readonly class AtomicRedisStorage implements RateLimitStorage
{
    /**
     * Lua script for atomic increment with TTL
     *
     * Increments a counter and sets TTL atomically.
     * Returns the new value.
     */
    private const string LUA_INCREMENT = <<<'LUA'
local key = KEYS[1]
local amount = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])

local current = redis.call('GET', key)
local newValue

if current == false then
    newValue = amount
    redis.call('SET', key, newValue, 'EX', ttl)
else
    newValue = redis.call('INCRBY', key, amount)
    -- Only set TTL if key doesn't have one (edge case recovery)
    local currentTtl = redis.call('TTL', key)
    if currentTtl == -1 then
        redis.call('EXPIRE', key, ttl)
    end
end

return newValue
LUA;

    /**
     * Lua script for atomic sliding window rate limiting
     *
     * Implements sliding window algorithm in a single atomic operation.
     * Returns: [allowed (0/1), remaining, resetAt, retryAfter]
     */
    private const string LUA_SLIDING_WINDOW = <<<'LUA'
local currentKey = KEYS[1]
local previousKey = KEYS[2]
local now = tonumber(ARGV[1])
local windowSize = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])

-- Calculate window boundaries
local windowStart = math.floor(now / windowSize) * windowSize
local windowEnd = windowStart + windowSize

-- Get counts
local currentCount = tonumber(redis.call('GET', currentKey) or 0)
local previousCount = tonumber(redis.call('GET', previousKey) or 0)

-- Calculate weighted count (sliding window approximation)
local elapsed = now - windowStart
local previousWeight = 1.0 - (elapsed / windowSize)
local weightedPrevious = math.floor(previousCount * previousWeight)
local totalCount = currentCount + weightedPrevious

-- Check if allowed
if totalCount + cost > limit then
    local retryAfter = windowEnd - now
    return {0, 0, windowEnd, retryAfter}
end

-- Increment current window atomically
local newCount = redis.call('INCRBY', currentKey, cost)

-- Set TTL (2x window for safety)
local ttl = windowSize * 2
local currentTtl = redis.call('TTL', currentKey)
if currentTtl == -1 then
    redis.call('EXPIRE', currentKey, ttl)
end

local remaining = limit - (newCount + weightedPrevious)
if remaining < 0 then remaining = 0 end

return {1, remaining, windowEnd, 0}
LUA;

    /**
     * Lua script for atomic token bucket rate limiting
     *
     * Implements token bucket algorithm in a single atomic operation.
     * Returns: [allowed (0/1), remaining, resetAt, retryAfter]
     */
    private const string LUA_TOKEN_BUCKET = <<<'LUA'
local key = KEYS[1]
local now = tonumber(ARGV[1])
local bucketSize = tonumber(ARGV[2])
local refillRate = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

-- Get current state
local data = redis.call('GET', key)
local tokens, lastRefill

if data then
    local decoded = cjson.decode(data)
    tokens = tonumber(decoded.tokens)
    lastRefill = tonumber(decoded.last_refill)
else
    tokens = bucketSize
    lastRefill = now
end

-- Calculate tokens to add
local elapsed = now - lastRefill
local tokensToAdd = math.floor(elapsed * refillRate)
tokens = math.min(bucketSize, tokens + tokensToAdd)

-- Calculate reset time
local tokensNeeded = bucketSize - tokens
local resetAt = now
if tokensNeeded > 0 then
    resetAt = now + math.ceil(tokensNeeded / refillRate)
end

-- Check if we can consume
if tokens < cost then
    local needed = cost - tokens
    local retryAfter = math.ceil(needed / refillRate)
    return {0, 0, now + retryAfter, retryAfter}
end

-- Consume tokens
tokens = tokens - cost

-- Store new state
local newData = cjson.encode({tokens = tokens, last_refill = now})
redis.call('SET', key, newData, 'EX', ttl)

return {1, tokens, resetAt, 0}
LUA;

    /**
     * @param object $client Redis or Predis\Client instance
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
        $result = $this->evalScript(
            self::LUA_INCREMENT,
            [$this->prefix . $key],
            [$amount, $ttl]
        );

        return (int) $result;
    }

    /**
     * Execute atomic sliding window rate limit check
     *
     * @param string $identifier Rate limit subject identifier
     * @param int $windowSize Window size in seconds
     * @param int $limit Maximum requests per window
     * @param int $cost Number of requests to consume
     *
     * @return array{allowed: bool, remaining: int, resetAt: int, retryAfter: int}
     *
     * @throws StorageException If Redis operation fails
     */
    public function atomicSlidingWindow(
        string $identifier,
        int $windowSize,
        int $limit,
        int $cost = 1,
    ): array {
        $now         = time();
        $windowStart = (int) floor($now / $windowSize) * $windowSize;

        $currentKey  = $this->prefix . $identifier . ':' . $windowStart;
        $previousKey = $this->prefix . $identifier . ':' . ($windowStart - $windowSize);

        $result = $this->evalScript(
            self::LUA_SLIDING_WINDOW,
            [$currentKey, $previousKey],
            [$now, $windowSize, $limit, $cost]
        );

        if (!is_array($result) || count($result) !== 4) {
            throw new StorageException('Invalid response from Redis Lua script');
        }

        return [
            'allowed'    => (int) $result[0] === 1,
            'remaining'  => (int) $result[1],
            'resetAt'    => (int) $result[2],
            'retryAfter' => (int) $result[3],
        ];
    }

    /**
     * Execute atomic token bucket rate limit check
     *
     * @param string $identifier Rate limit subject identifier
     * @param int $bucketSize Maximum tokens in bucket
     * @param float $refillRate Tokens per second
     * @param int $cost Tokens to consume
     * @param int $ttl State TTL in seconds
     *
     * @return array{allowed: bool, remaining: int, resetAt: int, retryAfter: int}
     *
     * @throws StorageException If Redis operation fails
     */
    public function atomicTokenBucket(
        string $identifier,
        int $bucketSize,
        float $refillRate,
        int $cost = 1,
        int $ttl = 3600,
    ): array {
        $key = $this->prefix . 'bucket:' . $identifier;

        $result = $this->evalScript(
            self::LUA_TOKEN_BUCKET,
            [$key],
            [time(), $bucketSize, $refillRate, $cost, $ttl]
        );

        if (!is_array($result) || count($result) !== 4) {
            throw new StorageException('Invalid response from Redis Lua script');
        }

        return [
            'allowed'    => (int) $result[0] === 1,
            'remaining'  => (int) $result[1],
            'resetAt'    => (int) $result[2],
            'retryAfter' => (int) $result[3],
        ];
    }

    /**
     * Execute a Lua script with automatic SHA caching
     *
     * @param string $script The Lua script
     * @param list<string> $keys Redis keys
     * @param list<int|float|string> $args Script arguments
     *
     * @return mixed Script result
     *
     * @throws StorageException If script execution fails
     */
    private function evalScript(string $script, array $keys, array $args): mixed
    {
        try {
            /** @phpstan-ignore method.notFound (Redis/Predis duck typing) */
            return $this->client->eval($script, array_merge($keys, $args), count($keys));
        } catch (Throwable $throwable) {
            throw new StorageException('Redis Lua script execution failed: ' . $throwable->getMessage(), 0, $throwable);
        }
    }
}
