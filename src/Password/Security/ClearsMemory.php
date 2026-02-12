<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Security;

use Throwable;

/**
 * Trait for secure memory clearing of sensitive data
 *
 * Provides methods to zero out sensitive data in memory after use,
 * using sodium_memzero when available for secure clearing.
 */
trait ClearsMemory
{
    /**
     * Clear sensitive data from memory
     *
     * Uses sodium_memzero for secure clearing. The sodium extension is required
     * because PHP strings are immutable and manual clearing (null bytes) is ineffective.
     *
     * Note: ext-sodium is a required dependency in composer.json.
     */
    protected function clearMemory(string &$data): void
    {
        // @codeCoverageIgnoreStart
        if (!function_exists('sodium_memzero')) {
            // This should never happen if composer requirements are respected.
            // Sodium extension is required - PHP strings are immutable, so
            // str_repeat("\0", ...) doesn't actually overwrite the original memory.
            return;
        }

        // @codeCoverageIgnoreEnd

        try {
            // @phpstan-ignore parameterByRef.type (sodium_memzero sets variable to null by design)
            sodium_memzero($data);
        } catch (Throwable) {
            // Variable may have been optimized away by the runtime
        }
    }

    /**
     * Execute a callback with sensitive data, then clear the data
     *
     * @template T
     *
     * @param string $sensitiveData The sensitive data to use
     * @param callable(string): T $callback The callback to execute
     *
     * @return T The callback result
     */
    protected function withClearedMemory(string $sensitiveData, callable $callback): mixed
    {
        try {
            return $callback($sensitiveData);
        } finally {
            $this->clearMemory($sensitiveData);
        }
    }
}
