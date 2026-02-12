<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Token;

use Override;
use Random\RandomException;

/**
 * CSRF token generator
 *
 * Generates cryptographically secure CSRF tokens.
 */
final class CsrfTokenGenerator implements CsrfTokenProvider
{
    /**
     * Default token size in bytes (256 bits)
     */
    public const int DEFAULT_BYTES = 32;

    private ?CsrfToken $token = null;

    public function __construct(
        private readonly int $bytes = self::DEFAULT_BYTES,
    ) {
    }

    /**
     * Get current token (generates if not exists)
     *
     * @throws RandomException If no suitable random source is available
     */
    #[Override]
    public function get(): CsrfToken
    {
        if (!$this->token instanceof CsrfToken) {
            $this->token = $this->generate();
        }

        return $this->token;
    }

    /**
     * Generate a new token
     *
     * @throws RandomException If no suitable random source is available
     */
    public function generate(): CsrfToken
    {
        $byteCount = max(CsrfToken::MIN_BYTES, $this->bytes);
        $bytes     = random_bytes($byteCount);
        $encoded   = base64_encode($bytes);

        return new CsrfToken($encoded);
    }

    /**
     * Reset token (for long-running processes)
     */
    #[Override]
    public function reset(): void
    {
        $this->token = null;
    }

    /**
     * Set an existing token
     */
    public function set(CsrfToken $token): void
    {
        $this->token = $token;
    }
}
