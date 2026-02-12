<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sri\Exception;

use RuntimeException;

/**
 * Exception thrown when resource hash doesn't match expected value
 */
final class HashMismatchException extends RuntimeException
{
    public function __construct(
        private readonly string $expected,
        private readonly string $actual,
    ) {
        parent::__construct('Resource hash does not match expected value');
    }

    /**
     * Get the expected hash
     */
    public function expected(): string
    {
        return $this->expected;
    }

    /**
     * Get the actual hash
     */
    public function actual(): string
    {
        return $this->actual;
    }

    /**
     * Create for mismatch
     */
    public static function mismatch(string $expected, string $actual): self
    {
        return new self($expected, $actual);
    }
}
