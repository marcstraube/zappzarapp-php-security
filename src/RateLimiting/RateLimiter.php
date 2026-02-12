<?php

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting;

use Zappzarapp\Security\RateLimiting\Exception\RateLimitException;

/**
 * Interface for rate limiters
 */
interface RateLimiter
{
    /**
     * Check if a request should be allowed and consume quota
     *
     * @param RateLimitIdentifier|string $identifier Rate limit subject identifier
     * @param int $cost Number of tokens/requests to consume
     *
     * @return RateLimitResult The result of the rate limit check
     */
    public function consume(RateLimitIdentifier|string $identifier, int $cost = 1): RateLimitResult;

    /**
     * Check rate limit status without consuming quota
     *
     * @param RateLimitIdentifier|string $identifier Rate limit subject identifier
     *
     * @return RateLimitResult The current rate limit status
     */
    public function peek(RateLimitIdentifier|string $identifier): RateLimitResult;

    /**
     * Check and throw exception if rate limited
     *
     * @param RateLimitIdentifier|string $identifier Rate limit subject identifier
     * @param int $cost Number of tokens/requests to consume
     *
     * @throws RateLimitException If rate limit is exceeded
     */
    public function consumeOrFail(RateLimitIdentifier|string $identifier, int $cost = 1): RateLimitResult;

    /**
     * Reset rate limit for an identifier
     *
     * @param RateLimitIdentifier|string $identifier Rate limit subject identifier
     */
    public function reset(RateLimitIdentifier|string $identifier): void;
}
