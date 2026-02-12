<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting;

use InvalidArgumentException;
use Override;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;
use Zappzarapp\Security\RateLimiting\Algorithm\AlgorithmType;
use Zappzarapp\Security\RateLimiting\Algorithm\RateLimitAlgorithm;
use Zappzarapp\Security\RateLimiting\Algorithm\SlidingWindow;
use Zappzarapp\Security\RateLimiting\Algorithm\TokenBucket;
use Zappzarapp\Security\RateLimiting\Exception\RateLimitException;
use Zappzarapp\Security\RateLimiting\Storage\InMemoryStorage;
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorage;

/**
 * Default rate limiter implementation
 *
 * ## Basic Usage
 *
 * ```php
 * $limiter = new DefaultRateLimiter();
 *
 * // Check rate limit
 * $result = $limiter->consume('user:123');
 *
 * if ($result->isDenied()) {
 *     $result->applyHeaders();
 *     http_response_code(429);
 *     exit;
 * }
 * ```
 *
 * ## With Custom Config
 *
 * ```php
 * $limiter = new DefaultRateLimiter(
 *     config: RateLimitConfig::api(),
 *     storage: new RedisStorage($redis)
 * );
 * ```
 */
final readonly class DefaultRateLimiter implements RateLimiter
{
    private RateLimitAlgorithm $algorithm;

    public function __construct(
        private RateLimitConfig $config = new RateLimitConfig(),
        ?RateLimitStorage $storage = null,
        private ?SecurityLoggerInterface $logger = null,
    ) {
        $storage ??= new InMemoryStorage();
        $this->algorithm = $this->createAlgorithm($storage);
    }

    #[Override]
    public function consume(RateLimitIdentifier|string $identifier, int $cost = 1): RateLimitResult
    {
        // Validate cost to prevent quota recovery attacks with negative values
        if ($cost < 1) {
            throw new InvalidArgumentException(
                'Cost must be at least 1. Negative or zero cost values are not allowed.'
            );
        }

        $result = $this->algorithm->consume($this->resolveIdentifier($identifier), $cost);

        if ($result->isDenied()) {
            $this->logger?->warning('Rate limit exceeded', [
                'identifier'  => $this->resolveIdentifier($identifier),
                'limit'       => $result->limit,
                'remaining'   => $result->remaining,
                'retry_after' => $result->retryAfter,
            ]);
        }

        return $result;
    }

    #[Override]
    public function peek(RateLimitIdentifier|string $identifier): RateLimitResult
    {
        return $this->algorithm->peek($this->resolveIdentifier($identifier));
    }

    #[Override]
    public function consumeOrFail(RateLimitIdentifier|string $identifier, int $cost = 1): RateLimitResult
    {
        $result = $this->consume($identifier, $cost);

        if ($result->isDenied()) {
            throw RateLimitException::exceeded($result->retryAfter, $result->limit);
        }

        return $result;
    }

    #[Override]
    public function reset(RateLimitIdentifier|string $identifier): void
    {
        $this->algorithm->reset($this->resolveIdentifier($identifier));
    }

    /**
     * Create appropriate algorithm instance
     */
    private function createAlgorithm(RateLimitStorage $storage): RateLimitAlgorithm
    {
        return match ($this->config->algorithm) {
            AlgorithmType::TOKEN_BUCKET   => new TokenBucket($storage, $this->config),
            AlgorithmType::SLIDING_WINDOW => new SlidingWindow($storage, $this->config),
        };
    }

    /**
     * Resolve identifier to string
     */
    private function resolveIdentifier(RateLimitIdentifier|string $identifier): string
    {
        if ($identifier instanceof RateLimitIdentifier) {
            return $identifier->value();
        }

        return $identifier;
    }

    /**
     * Create for API rate limiting
     */
    public static function api(?RateLimitStorage $storage = null): self
    {
        return new self(RateLimitConfig::api(), $storage);
    }

    /**
     * Create for login attempt limiting
     */
    public static function login(?RateLimitStorage $storage = null): self
    {
        return new self(RateLimitConfig::login(), $storage);
    }

    /**
     * Create for form submission limiting
     */
    public static function form(?RateLimitStorage $storage = null): self
    {
        return new self(RateLimitConfig::form(), $storage);
    }
}
