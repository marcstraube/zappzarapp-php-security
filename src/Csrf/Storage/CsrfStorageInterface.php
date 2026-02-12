<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Storage;

/**
 * Interface for CSRF token storage
 *
 * Implementations must ensure atomic operations for thread safety.
 */
interface CsrfStorageInterface
{
    /**
     * Store a CSRF token
     *
     * @param string $key Unique identifier for the token
     * @param string $token The token value
     * @param int|null $ttl Time-to-live in seconds (null = session lifetime)
     */
    public function store(string $key, string $token, ?int $ttl = null): void;

    /**
     * Retrieve a stored CSRF token
     *
     * @param string $key Unique identifier for the token
     * @return string|null The token value or null if not found/expired
     */
    public function retrieve(string $key): ?string;

    /**
     * Remove a CSRF token
     *
     * @param string $key Unique identifier for the token
     */
    public function remove(string $key): void;

    /**
     * Check if a token exists
     *
     * @param string $key Unique identifier for the token
     */
    public function has(string $key): bool;

    /**
     * Clear all stored tokens
     */
    public function clear(): void;
}
