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
 * Sliding Window rate limiting algorithm
 *
 * Uses weighted counting between current and previous windows to provide smoother
 * rate limiting than fixed windows. This approximation avoids the "burst at boundary"
 * problem where clients could make 2x requests by timing requests around window edges.
 *
 * ## Algorithm
 *
 * The sliding window uses two counters (current window + previous window) and
 * interpolates based on how far into the current window we are:
 *
 * ```
 * effectiveCount = currentWindowCount + (previousWindowCount * (1 - elapsedRatio))
 * ```
 *
 * ## Storage Considerations
 *
 * **Single-process PHP (PHP-FPM, mod_php):**
 * {@see InMemoryStorage} is safe to use since each request has isolated memory.
 * However, rate limits won't persist across requests - suitable only for testing.
 *
 * **Distributed/High-concurrency environments:**
 * Use {@see AtomicRedisStorage} which provides atomic sliding window operations
 * via Lua scripts, preventing race conditions where concurrent requests might
 * both pass the limit check before either increments the counter.
 *
 * ## TOCTOU Race Condition Warning
 *
 * **IMPORTANT:** This implementation has a Time-Of-Check-To-Time-Of-Use (TOCTOU)
 * race condition between reading the current count and incrementing it. In high-
 * concurrency environments, multiple requests may pass the limit check before
 * any of them increments the counter.
 *
 * **Mitigation strategies:**
 * 1. Use {@see AtomicRedisStorage} which performs check-and-increment atomically via Lua scripts
 * 2. Accept slight over-limit as acceptable (e.g., limit=100, actual max=102-105)
 * 3. Use distributed locking (adds latency, not recommended for rate limiting)
 *
 * For applications requiring strict rate limiting, always use AtomicRedisStorage
 * or another atomic storage backend.
 *
 * @see AtomicRedisStorage::atomicSlidingWindow() For atomic distributed rate limiting
 */
final readonly class SlidingWindow implements RateLimitAlgorithm
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

        // Get current window info
        $windowStart = $this->getWindowStart($now);
        $windowEnd   = $windowStart + $this->config->window;

        // Get current and previous window counts
        $currentKey  = $key . ':' . $windowStart;
        $previousKey = $key . ':' . ($windowStart - $this->config->window);

        $currentCount  = (int) ($this->storage->get($currentKey)['count'] ?? 0);
        $previousCount = (int) ($this->storage->get($previousKey)['count'] ?? 0);

        // Calculate weighted count (sliding window approximation)
        $elapsed          = $now - $windowStart;
        $previousWeight   = 1.0 - ((float) $elapsed / (float) $this->config->window);
        $weightedPrevious = (int) floor((float) $previousCount * $previousWeight);
        $totalCount       = $currentCount + $weightedPrevious;

        // Check if limit would be exceeded
        if ($totalCount + $cost > $this->config->limit) {
            $retryAfter = $windowEnd - $now;

            return RateLimitResult::denied(
                $this->config->limit,
                $windowEnd,
                $retryAfter
            );
        }

        // Increment current window
        $newCount  = $this->storage->increment($currentKey, $cost, $this->config->window * 2);
        $remaining = $this->config->limit - ($newCount + $weightedPrevious);

        return RateLimitResult::allowed(
            $this->config->limit,
            max(0, $remaining),
            $windowEnd
        );
    }

    #[Override]
    public function peek(string $identifier): RateLimitResult
    {
        $now = time();
        $key = $this->buildKey($identifier);

        $windowStart = $this->getWindowStart($now);
        $windowEnd   = $windowStart + $this->config->window;

        $currentKey  = $key . ':' . $windowStart;
        $previousKey = $key . ':' . ($windowStart - $this->config->window);

        $currentCount  = (int) ($this->storage->get($currentKey)['count'] ?? 0);
        $previousCount = (int) ($this->storage->get($previousKey)['count'] ?? 0);

        $elapsed          = $now - $windowStart;
        $previousWeight   = 1.0 - ((float) $elapsed / (float) $this->config->window);
        $weightedPrevious = (int) floor((float) $previousCount * $previousWeight);
        $totalCount       = $currentCount + $weightedPrevious;

        $remaining = $this->config->limit - $totalCount;

        if ($remaining <= 0) {
            return RateLimitResult::denied(
                $this->config->limit,
                $windowEnd,
                $windowEnd - $now
            );
        }

        return RateLimitResult::allowed(
            $this->config->limit,
            $remaining,
            $windowEnd
        );
    }

    #[Override]
    public function reset(string $identifier): void
    {
        $now         = time();
        $key         = $this->buildKey($identifier);
        $windowStart = $this->getWindowStart($now);

        $this->storage->delete($key . ':' . $windowStart);
        $this->storage->delete($key . ':' . ($windowStart - $this->config->window));
    }

    /**
     * Build storage key
     */
    private function buildKey(string $identifier): string
    {
        return $this->config->prefix . $identifier;
    }

    /**
     * Get the start of the current window
     */
    private function getWindowStart(int $now): int
    {
        return (int) floor($now / $this->config->window) * $this->config->window;
    }
}
