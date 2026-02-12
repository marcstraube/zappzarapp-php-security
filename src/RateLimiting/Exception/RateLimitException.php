<?php

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Exception;

use RuntimeException;

/**
 * Exception thrown when rate limit is exceeded
 */
final class RateLimitException extends RuntimeException
{
    public function __construct(
        private readonly int $retryAfter,
        private readonly int $limit,
        private readonly int $remaining,
    ) {
        parent::__construct(sprintf(
            'Rate limit exceeded. Retry after %d seconds.',
            $retryAfter
        ));
    }

    /**
     * Get seconds until rate limit resets
     */
    public function retryAfter(): int
    {
        return $this->retryAfter;
    }

    /**
     * Get the rate limit
     */
    public function limit(): int
    {
        return $this->limit;
    }

    /**
     * Get remaining requests
     */
    public function remaining(): int
    {
        return $this->remaining;
    }

    /**
     * Create for exceeded limit
     */
    public static function exceeded(int $retryAfter, int $limit): self
    {
        return new self($retryAfter, $limit, 0);
    }
}
