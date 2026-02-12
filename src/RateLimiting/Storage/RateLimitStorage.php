<?php

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Storage;

/**
 * Interface for rate limit storage
 */
interface RateLimitStorage
{
    /**
     * Get a value from storage
     *
     * @param string $key The key to retrieve
     *
     * @return array<string, mixed>|null The stored data or null if not found
     */
    public function get(string $key): ?array;

    /**
     * Set a value in storage
     *
     * @param string $key The key to store
     * @param array<string, mixed> $data The data to store
     * @param int $ttl Time-to-live in seconds
     */
    public function set(string $key, array $data, int $ttl): void;

    /**
     * Delete a value from storage
     *
     * @param string $key The key to delete
     */
    public function delete(string $key): void;

    /**
     * Atomically increment a counter
     *
     * @param string $key The key to increment
     * @param int $amount Amount to increment by
     * @param int $ttl Time-to-live in seconds
     *
     * @return int The new value after increment
     */
    public function increment(string $key, int $amount, int $ttl): int;
}
