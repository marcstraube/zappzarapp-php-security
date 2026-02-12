<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Token;

use Random\RandomException;

/**
 * Interface for CSRF token providers
 */
interface CsrfTokenProvider
{
    /**
     * Get the current CSRF token (generates if needed)
     *
     * @throws RandomException If no suitable random source is available
     */
    public function get(): CsrfToken;

    /**
     * Reset the token (for long-running processes)
     */
    public function reset(): void;
}
