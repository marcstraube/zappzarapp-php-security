<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Nonce;

use Random\RandomException;

/**
 * Provides CSP nonces for script and style tags
 *
 * Allows different nonce strategies (cryptographic, null for tests, etc.)
 */
interface NonceProvider
{
    /**
     * Get current nonce value
     *
     * @return string Base64-encoded nonce (or empty for NullNonce)
     * @throws RandomException If no suitable random source is available
     */
    public function get(): string;
}
