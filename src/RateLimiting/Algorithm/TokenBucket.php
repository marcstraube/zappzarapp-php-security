<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive
 * @noinspection DuplicatedCode Intentional: consume() and peek() are self-contained for readability
 */

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Algorithm;

use Override;
use Zappzarapp\Security\RateLimiting\RateLimitConfig;
use Zappzarapp\Security\RateLimiting\RateLimitResult;
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorage;

/**
 * Token Bucket rate limiting algorithm
 *
 * Tokens are added at a fixed rate up to a maximum bucket size. This algorithm
 * allows controlled burst traffic (up to bucket size) while enforcing an average
 * rate over time. Ideal for APIs where occasional bursts are acceptable but
 * sustained high traffic should be limited.
 *
 * ## Algorithm
 *
 * - Bucket starts full (size = limit or burst if configured)
 * - Each request consumes tokens (default: 1)
 * - Tokens refill at a steady rate: `limit / window` tokens per second
 * - Requests are denied when insufficient tokens are available
 *
 * ## Storage Considerations
 *
 * **Single-process PHP (PHP-FPM, mod_php):**
 * {@see InMemoryStorage} is safe to use since each request has isolated memory.
 * However, token state won't persist across requests - suitable only for testing.
 *
 * **Distributed/High-concurrency environments:**
 * Use {@see AtomicRedisStorage} which provides atomic token bucket operations
 * via Lua scripts, preventing race conditions in the read-modify-write cycle
 * (reading current tokens, calculating refill, consuming tokens).
 *
 * ## TOCTOU Race Condition Warning
 *
 * **IMPORTANT:** This implementation has a Time-Of-Check-To-Time-Of-Use (TOCTOU)
 * race condition in the read-modify-write cycle. Concurrent requests may:
 * 1. Read the same token count
 * 2. Both pass the availability check
 * 3. Both consume tokens, resulting in negative effective balance
 *
 * **Mitigation strategies:**
 * 1. Use {@see AtomicRedisStorage} which performs the entire operation atomically via Lua scripts
 * 2. Accept slight over-limit as acceptable (e.g., limit=100, actual max=102-105)
 * 3. Use distributed locking (adds latency, not recommended for rate limiting)
 *
 * For applications requiring strict rate limiting, always use AtomicRedisStorage
 * or another atomic storage backend.
 *
 * @see AtomicRedisStorage::atomicTokenBucket() For atomic distributed rate limiting
 */
final readonly class TokenBucket implements RateLimitAlgorithm
{
    public function __construct(
        private RateLimitStorage $storage,
        private RateLimitConfig $config,
    ) {
    }

    #[Override]
    public function consume(string $identifier, int $cost = 1): RateLimitResult
    {
        $now = time();
        $key = $this->buildKey($identifier);

        // Get or initialize bucket state
        $state      = $this->storage->get($key);
        $tokens     = (int) ($state['tokens'] ?? $this->getBucketSize());
        $lastRefill = (int) ($state['last_refill'] ?? $now);

        // Calculate tokens to add based on time passed
        $elapsed     = $now - $lastRefill;
        $refillRate  = (float) $this->config->limit / (float) $this->config->window;
        $tokensToAdd = (int) floor((float) $elapsed * $refillRate);
        $tokens      = min($this->getBucketSize(), $tokens + $tokensToAdd);

        // Calculate when bucket will be full (for reset time)
        $tokensNeeded = $this->getBucketSize() - $tokens;
        $resetAt      = $tokensNeeded > 0
            ? $now + (int) ceil((float) $tokensNeeded / $refillRate)
            : $now;

        // Check if we can consume
        if ($tokens < $cost) {
            // Calculate when enough tokens will be available
            $tokensNeeded = $cost - $tokens;
            $retryAfter   = (int) ceil((float) $tokensNeeded / $refillRate);

            return RateLimitResult::denied(
                $this->config->limit,
                $now + $retryAfter,
                $retryAfter
            );
        }

        // Consume tokens
        $tokens -= $cost;

        // Store new state
        $this->storage->set($key, [
            'tokens'      => $tokens,
            'last_refill' => $now,
        ], $this->config->window * 2);

        return RateLimitResult::allowed(
            $this->config->limit,
            (int) $tokens,
            $resetAt
        );
    }

    #[Override]
    public function peek(string $identifier): RateLimitResult
    {
        $now = time();
        $key = $this->buildKey($identifier);

        $state      = $this->storage->get($key);
        $tokens     = (int) ($state['tokens'] ?? $this->getBucketSize());
        $lastRefill = (int) ($state['last_refill'] ?? $now);

        // Calculate current tokens
        $elapsed     = $now - $lastRefill;
        $refillRate  = (float) $this->config->limit / (float) $this->config->window;
        $tokensToAdd = (int) floor((float) $elapsed * $refillRate);
        $tokens      = min($this->getBucketSize(), $tokens + $tokensToAdd);

        $tokensNeeded = $this->getBucketSize() - $tokens;
        $resetAt      = $tokensNeeded > 0
            ? $now + (int) ceil((float) $tokensNeeded / $refillRate)
            : $now;

        if ($tokens < 1) {
            $retryAfter = (int) ceil(1.0 / $refillRate);

            return RateLimitResult::denied(
                $this->config->limit,
                $now + $retryAfter,
                $retryAfter
            );
        }

        return RateLimitResult::allowed(
            $this->config->limit,
            $tokens,
            $resetAt
        );
    }

    #[Override]
    public function reset(string $identifier): void
    {
        $this->storage->delete($this->buildKey($identifier));
    }

    /**
     * Get the maximum bucket size
     */
    private function getBucketSize(): int
    {
        return $this->config->burst > 0
            ? $this->config->burst
            : $this->config->limit;
    }

    /**
     * Build storage key
     */
    private function buildKey(string $identifier): string
    {
        return $this->config->prefix . 'bucket:' . $identifier;
    }
}
