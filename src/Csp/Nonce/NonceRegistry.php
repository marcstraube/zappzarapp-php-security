<?php
/** @noinspection PhpMultipleClassDeclarationsInspection - Psalm stubs conflict with native PHP 8.3 Override */

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Nonce;

use Random\RandomException;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;

/**
 * CSP Nonce Registry
 *
 * Provides singleton-like access to a shared NonceGenerator instance.
 * Ensures the same nonce is used throughout a single request.
 *
 * ## Basic Usage
 *
 * ```php
 * use Zappzarapp\Security\Csp\Nonce\NonceRegistry;
 *
 * // Get nonce for inline scripts/styles
 * $nonce = NonceRegistry::get();
 * echo "<script nonce=\"{$nonce}\">console.log('Safe!');</script>";
 * ```
 *
 * ## Long-Running Processes (Swoole, RoadRunner)
 *
 * ```php
 * // At the start of each request
 * NonceRegistry::reset();
 *
 * // Then use normally
 * $nonce = NonceRegistry::get();
 * ```
 *
 * ## Framework Integration
 *
 * ```php
 * // Override with framework-provided nonce
 * NonceRegistry::set($request->getAttribute('csp-nonce'));
 * ```
 *
 * @see NonceGenerator For instance-based usage (DI containers)
 * @see HeaderBuilder::build() Accepts NonceRegistry::generator() as provider
 *
 * @note For async environments (Swoole, RoadRunner with coroutines, Fibers),
 *       prefer NonceGenerator with dependency injection for thread-safety.
 */
final class NonceRegistry
{
    use ValidatesNonce;

    private static ?NonceGenerator $generator = null;

    /**
     * Prevent instantiation (static-only class)
     *
     * @psalm-suppress UnusedConstructor Private constructor prevents instantiation
     * @codeCoverageIgnore Private constructor prevents instantiation
     */
    private function __construct()
    {
    }

    /**
     * Get the shared NonceGenerator instance
     *
     * Creates instance on first access (lazy initialization).
     * Use this when you need the generator for HeaderBuilder.
     *
     * ```php
     * $csp = HeaderBuilder::build($directives, NonceRegistry::generator());
     * ```
     */
    public static function generator(): NonceGenerator
    {
        if (!self::$generator instanceof NonceGenerator) {
            self::$generator = new NonceGenerator();
        }

        return self::$generator;
    }

    /**
     * Get the current nonce value
     *
     * Convenience method - equivalent to generator()->get()
     *
     * @return string Base64-encoded cryptographically secure nonce
     *
     * @throws RandomException If no suitable random source is available
     */
    public static function get(): string
    {
        return self::generator()->get();
    }

    /**
     * Set nonce from external source
     *
     * Use when CSP header has already been set with a known nonce,
     * or when integrating with a framework that provides its own nonce.
     * Validates input to prevent CSP injection attacks (Defense in Depth).
     *
     * @param string $nonce External nonce value (base64-encoded recommended)
     *
     * @throws InvalidDirectiveValueException If nonce contains invalid characters
     */
    public static function set(string $nonce): void
    {
        self::validateNonceValue($nonce);
        self::generator()->set($nonce);
    }

    /**
     * Reset for new request (long-running processes)
     *
     * Call at the start of each request in long-running processes
     * (Swoole, RoadRunner, etc.) to ensure a fresh nonce per request.
     *
     * Creates a new generator instance on next access, ensuring
     * complete isolation between requests.
     */
    public static function reset(): void
    {
        self::$generator = null;
    }

}