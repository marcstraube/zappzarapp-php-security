<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Storage;

use Override;

/**
 * In-memory rate limit storage
 *
 * Stores rate limit data in PHP process memory. Data is not shared between
 * processes and is lost when the process ends.
 *
 * ## Race Conditions: When They Do (and Don't) Apply
 *
 * **Standard PHP-FPM / mod_php (NO race conditions):**
 *
 * In traditional PHP deployments, each HTTP request spawns a separate process
 * (or uses a process from a pool). Crucially, PHP arrays and objects are NOT
 * shared between these processes. Each request gets its own isolated memory
 * space. This means InMemoryStorage is inherently safe in this model - there's
 * simply no shared state that could race.
 *
 * **Async/Persistent PHP Runtimes (race conditions ARE possible):**
 *
 * When using long-running PHP processes that handle multiple requests:
 * - Swoole / OpenSwoole: Worker processes handle multiple requests, sharing memory
 * - ReactPHP / Amp: Single-process event loops serving concurrent requests
 * - Fibers with shared state: Co-routines accessing shared InMemoryStorage
 * - FrankenPHP (worker mode): Long-lived workers with shared memory
 *
 * In these environments, concurrent requests CAN access the same InMemoryStorage
 * instance, creating potential race conditions in the check-then-increment pattern.
 *
 * ## Suitable Use Cases
 *
 * - Unit and integration tests (predictable, no external dependencies)
 * - CLI tools processing single requests
 * - Development and learning environments
 * - Single-request PHP-FPM/mod_php where persistence isn't needed
 *
 * ## Production Recommendations
 *
 * For production environments requiring shared state across requests or processes,
 * use {@see AtomicRedisStorage} which provides atomic operations via Lua scripts
 * to prevent race conditions in any PHP runtime model.
 *
 * @see AtomicRedisStorage For distributed/high-concurrency production environments
 */
final class InMemoryStorage implements RateLimitStorage
{
    /**
     * Maximum number of keys to prevent memory exhaustion (DoS protection)
     */
    private const int MAX_KEYS = 10000;

    /**
     * @var array<string, array{data: array<string, mixed>, expires: int}>
     */
    private array $data = [];

    /**
     * @var array<string, array{value: int, expires: int}>
     */
    private array $counters = [];

    #[Override]
    public function get(string $key): ?array
    {
        $this->cleanup();

        if (!isset($this->data[$key])) {
            return null;
        }

        $entry = $this->data[$key];
        if ($entry['expires'] < time()) {
            unset($this->data[$key]);

            return null;
        }

        return $entry['data'];
    }

    #[Override]
    public function set(string $key, array $data, int $ttl): void
    {
        // Enforce key limit to prevent memory exhaustion
        if (!isset($this->data[$key]) && count($this->data) >= self::MAX_KEYS) {
            $this->cleanup();
            // If still at limit after cleanup, evict oldest entry
            if (count($this->data) >= self::MAX_KEYS) {
                $this->evictOldestData();
            }
        }

        $this->data[$key] = [
            'data'    => $data,
            'expires' => time() + $ttl,
        ];
    }

    #[Override]
    public function delete(string $key): void
    {
        unset($this->data[$key], $this->counters[$key]);
    }

    #[Override]
    public function increment(string $key, int $amount, int $ttl): int
    {
        $now = time();

        // Check if counter exists and is not expired
        if (isset($this->counters[$key]) && $this->counters[$key]['expires'] >= $now) {
            $this->counters[$key]['value'] += $amount;

            return $this->counters[$key]['value'];
        }

        // Enforce key limit to prevent memory exhaustion
        if (!isset($this->counters[$key]) && count($this->counters) >= self::MAX_KEYS) {
            $this->cleanup();
            // If still at limit after cleanup, evict oldest entry
            if (count($this->counters) >= self::MAX_KEYS) {
                $this->evictOldestCounter();
            }
        }

        // Create new counter
        $this->counters[$key] = [
            'value'   => $amount,
            'expires' => $now + $ttl,
        ];

        return $amount;
    }

    /**
     * Clear all data
     */
    public function clear(): void
    {
        $this->data     = [];
        $this->counters = [];
    }

    /**
     * Get count of stored entries (for testing)
     */
    public function count(): int
    {
        return count($this->data) + count($this->counters);
    }

    /**
     * Clean up expired entries
     */
    private function cleanup(): void
    {
        $now = time();

        foreach ($this->data as $key => $entry) {
            if ($entry['expires'] < $now) {
                unset($this->data[$key]);
            }
        }

        foreach ($this->counters as $key => $entry) {
            if ($entry['expires'] < $now) {
                unset($this->counters[$key]);
            }
        }
    }

    /**
     * Evict the oldest data entry when at capacity
     */
    private function evictOldestData(): void
    {
        $oldestKey     = null;
        $oldestExpires = PHP_INT_MAX;

        foreach ($this->data as $key => $entry) {
            if ($entry['expires'] < $oldestExpires) {
                $oldestExpires = $entry['expires'];
                $oldestKey     = $key;
            }
        }

        if ($oldestKey !== null) {
            unset($this->data[$oldestKey]);
        }
    }

    /**
     * Evict the oldest counter entry when at capacity
     */
    private function evictOldestCounter(): void
    {
        $oldestKey     = null;
        $oldestExpires = PHP_INT_MAX;

        foreach ($this->counters as $key => $entry) {
            if ($entry['expires'] < $oldestExpires) {
                $oldestExpires = $entry['expires'];
                $oldestKey     = $key;
            }
        }

        if ($oldestKey !== null) {
            unset($this->counters[$oldestKey]);
        }
    }
}
