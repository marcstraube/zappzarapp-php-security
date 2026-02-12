<?php

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting\Algorithm;

/**
 * Rate limiting algorithm types
 */
enum AlgorithmType: string
{
    /**
     * Token Bucket algorithm
     *
     * Allows burst traffic while enforcing average rate.
     * Tokens are added at a fixed rate up to a maximum bucket size.
     */
    case TOKEN_BUCKET = 'token_bucket';

    /**
     * Sliding Window algorithm
     *
     * Counts requests in a sliding time window.
     * More accurate than fixed window but more expensive.
     */
    case SLIDING_WINDOW = 'sliding_window';
}
