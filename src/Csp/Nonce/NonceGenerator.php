<?php
/** @noinspection PhpMultipleClassDeclarationsInspection - Psalm stubs conflict with native PHP 8.3 Override */

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Nonce;

use Override;
use Random\RandomException;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;

/**
 * CSP Nonce Generator
 *
 * Generates cryptographically secure nonces for Content Security Policy.
 * Instance-based to ensure safe usage in long-running processes (Swoole, RoadRunner).
 *
 * ## Basic Usage
 *
 * ```php
 * use Zappzarapp\Security\Csp\Nonce\NonceGenerator;
 *
 * $generator = new NonceGenerator();
 *
 * // Get nonce (generates once per instance, then returns cached value)
 * $nonce = $generator->get();
 *
 * // Use in HTML templates
 * echo "<script nonce=\"{$nonce}\">console.log('Safe!');</script>";
 * echo "<style nonce=\"{$nonce}\">body { margin: 0; }</style>";
 * ```
 *
 * ## Framework Integration
 *
 * ```php
 * $generator = new NonceGenerator();
 *
 * // Override with framework-provided nonce
 * $generator->set($request->getAttribute('csp-nonce'));
 *
 * // Reset for new request (long-running processes)
 * $generator->reset();
 * ```
 *
 * @see HeaderBuilder::build() Automatically uses this generator
 */
final class NonceGenerator implements NonceProvider
{
    use ValidatesNonce;

    private ?string $nonce = null;

    /**
     * Nonce size in bytes (256 bits, consistent with CSRF tokens)
     */
    private const int NONCE_BYTES = 32;

    /**
     * Get current nonce (generates if not exists)
     *
     * @return string Base64-encoded cryptographically secure nonce (256 bits)
     * @throws RandomException If no suitable random source is available
     */
    #[Override]
    public function get(): string
    {
        if ($this->nonce === null) {
            $this->nonce = base64_encode(random_bytes(self::NONCE_BYTES));
        }

        return $this->nonce;
    }

    /**
     * Set nonce from external source
     *
     * Allows host project to override the nonce if it has its own CSP implementation.
     * Validates input to prevent CSP injection attacks.
     *
     * @param string $nonce External nonce value (base64-encoded recommended)
     * @throws InvalidDirectiveValueException If nonce contains invalid characters
     */
    public function set(string $nonce): void
    {
        self::validateNonceValue($nonce);
        $this->nonce = $nonce;
    }

    /**
     * Reset nonce (for long-running processes)
     *
     * Call this at the beginning of each request in long-running processes
     * (Swoole, RoadRunner, etc.) to ensure a fresh nonce per request.
     */
    public function reset(): void
    {
        $this->nonce = null;
    }

}
