<?php
/** @noinspection PhpMultipleClassDeclarationsInspection - Psalm stubs conflict with native PHP 8.3 Override */

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Nonce;

use Override;

/**
 * Null Object Pattern for CSP nonces
 *
 * Provides empty nonce for testing or when CSP is disabled.
 * Useful for integration tests where nonce validation is not needed.
 */
final class NullNonce implements NonceProvider
{
    #[Override]
    public function get(): string
    {
        return '';
    }
}
