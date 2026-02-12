<?php

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Algorithm;

use Zappzarapp\Security\RateLimiting\RateLimitResult;

/**
 * Interface for rate limiting algorithms
 */
interface RateLimitAlgorithm
{
    /**
     * Attempt to consume a request
     *
     * @param string $identifier Unique identifier for the rate limit subject
     * @param int $cost Number of tokens/requests to consume
     *
     * @return RateLimitResult The result of the rate limit check
     */
    public function consume(string $identifier, int $cost = 1): RateLimitResult;

    /**
     * Get current state without consuming
     *
     * @param string $identifier Unique identifier for the rate limit subject
     *
     * @return RateLimitResult The current rate limit state
     */
    public function peek(string $identifier): RateLimitResult;

    /**
     * Reset rate limit for an identifier
     *
     * @param string $identifier Unique identifier to reset
     */
    public function reset(string $identifier): void;
}
