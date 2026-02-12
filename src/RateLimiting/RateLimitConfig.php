<?php

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting;

use InvalidArgumentException;
use Zappzarapp\Security\RateLimiting\Algorithm\AlgorithmType;

/**
 * Rate limit configuration
 */
final readonly class RateLimitConfig
{
    /**
     * @param int $limit Maximum requests per window
     * @param int $window Time window in seconds
     * @param AlgorithmType $algorithm Algorithm to use
     * @param int $burst Maximum burst size (for token bucket)
     * @param string $prefix Key prefix for storage
     *
     * @throws InvalidArgumentException If limit <= 0, window <= 0, or burst < 0
     */
    public function __construct(
        public int $limit = 100,
        public int $window = 3600,
        public AlgorithmType $algorithm = AlgorithmType::SLIDING_WINDOW,
        public int $burst = 0,
        public string $prefix = 'rate_limit:',
    ) {
        if ($limit <= 0) {
            throw new InvalidArgumentException('Limit must be greater than 0');
        }

        if ($window <= 0) {
            throw new InvalidArgumentException('Window must be greater than 0');
        }

        if ($burst < 0) {
            throw new InvalidArgumentException('Burst must be greater than or equal to 0');
        }
    }

    /**
     * Create with custom limit
     *
     * @throws InvalidArgumentException If limit <= 0
     */
    public function withLimit(int $limit): self
    {
        return new self($limit, $this->window, $this->algorithm, $this->burst, $this->prefix);
    }

    /**
     * Create with custom window
     *
     * @throws InvalidArgumentException If window <= 0
     */
    public function withWindow(int $window): self
    {
        return new self($this->limit, $window, $this->algorithm, $this->burst, $this->prefix);
    }

    /**
     * Create with custom algorithm
     */
    public function withAlgorithm(AlgorithmType $algorithm): self
    {
        return new self($this->limit, $this->window, $algorithm, $this->burst, $this->prefix);
    }

    /**
     * Create with burst allowance
     *
     * @throws InvalidArgumentException If burst < 0
     */
    public function withBurst(int $burst): self
    {
        return new self($this->limit, $this->window, $this->algorithm, $burst, $this->prefix);
    }

    /**
     * Create with custom prefix
     */
    public function withPrefix(string $prefix): self
    {
        return new self($this->limit, $this->window, $this->algorithm, $this->burst, $prefix);
    }

    /**
     * Create for API rate limiting (1000/hour)
     */
    public static function api(): self
    {
        return new self(
            limit: 1000,
            window: 3600,
            algorithm: AlgorithmType::SLIDING_WINDOW
        );
    }

    /**
     * Create for login attempt limiting (5/15min)
     */
    public static function login(): self
    {
        return new self(
            limit: 5,
            window: 900,
            algorithm: AlgorithmType::SLIDING_WINDOW,
            prefix: 'login_limit:'
        );
    }

    /**
     * Create for form submission limiting (10/min)
     */
    public static function form(): self
    {
        return new self(
            limit: 10,
            window: 60,
            algorithm: AlgorithmType::SLIDING_WINDOW,
            prefix: 'form_limit:'
        );
    }

    /**
     * Create for strict rate limiting (per second)
     *
     * @throws InvalidArgumentException If requestsPerSecond <= 0
     */
    public static function strict(int $requestsPerSecond): self
    {
        if ($requestsPerSecond <= 0) {
            throw new InvalidArgumentException('Requests per second must be greater than 0');
        }

        return new self(
            limit: $requestsPerSecond,
            window: 1,
            algorithm: AlgorithmType::TOKEN_BUCKET,
            burst: $requestsPerSecond * 2
        );
    }
}
