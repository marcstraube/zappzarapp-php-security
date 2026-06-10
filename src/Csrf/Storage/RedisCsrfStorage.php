<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Storage;

use Override;

/**
 * Redis-based CSRF token storage
 *
 * Supports both phpredis extension (Redis class) and Predis client via duck
 * typing. Enables distributed/stateless CSRF protection where tokens must be
 * shared across application instances.
 *
 * Tokens are stored under a configurable key prefix. A non-null TTL maps to a
 * Redis key expiry; a null TTL stores the token without expiry ("session
 * lifetime" semantics).
 *
 * @psalm-suppress MixedReturnStatement
 * @psalm-suppress MixedAssignment
 * @psalm-suppress MixedMethodCall
 * @psalm-suppress MixedArgument
 */
final readonly class RedisCsrfStorage implements CsrfStorageInterface
{
    /**
     * @param object $client Redis or Predis\Client instance with get/set/setex/del/keys methods
     * @param string $prefix Key prefix for namespacing
     */
    public function __construct(
        private object $client,
        private string $prefix = 'csrf:',
    ) {
    }

    #[Override]
    public function store(string $key, string $token, ?int $ttl = null): void
    {
        $prefixedKey = $this->prefix . $key;

        if ($ttl !== null && $ttl > 0) {
            /** @phpstan-ignore method.notFound (Redis/Predis duck typing) */
            $this->client->setex($prefixedKey, $ttl, $token);

            return;
        }

        /** @phpstan-ignore method.notFound (Redis/Predis duck typing) */
        $this->client->set($prefixedKey, $token);
    }

    #[Override]
    public function retrieve(string $key): ?string
    {
        /** @phpstan-ignore method.notFound (Redis/Predis duck typing) */
        $data = $this->client->get($this->prefix . $key);

        return is_string($data) ? $data : null;
    }

    #[Override]
    public function remove(string $key): void
    {
        /** @phpstan-ignore method.notFound (Redis/Predis duck typing) */
        $this->client->del($this->prefix . $key);
    }

    #[Override]
    public function has(string $key): bool
    {
        return $this->retrieve($key) !== null;
    }

    /**
     * Remove every token stored under the configured prefix
     *
     * Uses the KEYS command to enumerate matching keys. KEYS scans the whole
     * keyspace and should be treated as a maintenance operation, not part of a
     * hot request path.
     */
    #[Override]
    public function clear(): void
    {
        /** @var list<string> $keys */
        $keys = $this->client->keys($this->prefix . '*'); // @phpstan-ignore method.notFound

        if ($keys === []) {
            return;
        }

        /** @phpstan-ignore method.notFound (Redis/Predis duck typing) */
        $this->client->del($keys);
    }
}
