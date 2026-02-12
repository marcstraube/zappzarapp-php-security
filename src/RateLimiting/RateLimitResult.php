<?php

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting;

/**
 * Rate limit check result
 */
final readonly class RateLimitResult
{
    /**
     * @param bool $allowed Whether the request is allowed
     * @param int $limit Maximum requests per window
     * @param int $remaining Remaining requests in window
     * @param int $resetAt Unix timestamp when the limit resets
     * @param int $retryAfter Seconds until next request allowed (0 if allowed)
     */
    public function __construct(
        public bool $allowed,
        public int $limit,
        public int $remaining,
        public int $resetAt,
        public int $retryAfter = 0,
    ) {
    }

    /**
     * Check if request was allowed
     */
    public function isAllowed(): bool
    {
        return $this->allowed;
    }

    /**
     * Check if request was denied
     */
    public function isDenied(): bool
    {
        return !$this->allowed;
    }

    /**
     * Get rate limit headers
     *
     * @return array<string, string>
     */
    public function toHeaders(): array
    {
        $headers = [
            'X-RateLimit-Limit'     => (string) $this->limit,
            'X-RateLimit-Remaining' => (string) max(0, $this->remaining),
            'X-RateLimit-Reset'     => (string) $this->resetAt,
        ];

        if (!$this->allowed) {
            $headers['Retry-After'] = (string) $this->retryAfter;
        }

        return $headers;
    }

    /**
     * Apply rate limit headers to response
     *
     * @param bool $replace Replace existing headers
     */
    public function applyHeaders(bool $replace = true): void
    {
        foreach ($this->toHeaders() as $name => $value) {
            header($name . ': ' . $value, $replace);
        }
    }

    /**
     * Create allowed result
     */
    public static function allowed(int $limit, int $remaining, int $resetAt): self
    {
        return new self(true, $limit, $remaining, $resetAt);
    }

    /**
     * Create denied result
     */
    public static function denied(int $limit, int $resetAt, int $retryAfter): self
    {
        return new self(false, $limit, 0, $resetAt, $retryAfter);
    }
}
