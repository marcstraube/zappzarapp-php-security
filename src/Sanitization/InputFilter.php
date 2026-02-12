<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization;

/**
 * Interface for input filters
 */
interface InputFilter
{
    /**
     * Sanitize input
     *
     * @param string $input The input to sanitize
     *
     * @return string The sanitized input
     */
    public function sanitize(string $input): string;

    /**
     * Check if input is safe without sanitizing
     *
     * @param string $input The input to check
     *
     * @return bool True if input is safe
     */
    public function isSafe(string $input): bool;
}
