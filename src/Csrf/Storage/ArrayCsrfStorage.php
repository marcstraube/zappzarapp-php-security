<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Storage;

use Override;

/**
 * In-memory CSRF token storage for testing
 *
 * Not suitable for production - tokens are lost when script ends.
 * Use SessionCsrfStorage for web applications.
 */
final class ArrayCsrfStorage implements CsrfStorageInterface
{
    /**
     * @var array<string, array{token: string, expires: int|null}>
     */
    private array $tokens = [];

    #[Override]
    public function store(string $key, string $token, ?int $ttl = null): void
    {
        $this->tokens[$key] = [
            'token'   => $token,
            'expires' => $ttl !== null ? time() + $ttl : null,
        ];
    }

    #[Override]
    public function retrieve(string $key): ?string
    {
        if (!isset($this->tokens[$key])) {
            return null;
        }

        $data = $this->tokens[$key];

        // Check expiration
        if ($data['expires'] !== null && $data['expires'] < time()) {
            unset($this->tokens[$key]);

            return null;
        }

        return $data['token'];
    }

    #[Override]
    public function remove(string $key): void
    {
        unset($this->tokens[$key]);
    }

    #[Override]
    public function has(string $key): bool
    {
        return $this->retrieve($key) !== null;
    }

    #[Override]
    public function clear(): void
    {
        $this->tokens = [];
    }

    /**
     * Get count of stored tokens (for testing)
     */
    public function count(): int
    {
        return count($this->tokens);
    }
}
