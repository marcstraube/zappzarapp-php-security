<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sri;

/**
 * Configuration for resource fetcher
 */
final readonly class ResourceFetcherConfig
{
    public function __construct(
        public int $timeout = 10,
        public int $maxSize = 10485760, // 10 MB
        public bool $followRedirects = true,
        public int $maxRedirects = 5,
        public string $userAgent = 'Zappzarapp-Security-SRI/1.0',
        public bool $requireHttps = true, // Only allow HTTPS in production
    ) {
    }

    /**
     * Create config for development (allows HTTP)
     *
     * WARNING: Only use for local development. HTTP resources can be
     * modified by MITM attacks, making SRI hashes unreliable.
     */
    public static function development(): self
    {
        return new self(requireHttps: false);
    }

    /**
     * Create with custom timeout
     */
    public function withTimeout(int $timeout): self
    {
        return new self(
            $timeout,
            $this->maxSize,
            $this->followRedirects,
            $this->maxRedirects,
            $this->userAgent
        );
    }

    /**
     * Create with custom max size
     */
    public function withMaxSize(int $maxSize): self
    {
        return new self(
            $this->timeout,
            $maxSize,
            $this->followRedirects,
            $this->maxRedirects,
            $this->userAgent
        );
    }

    /**
     * Create with redirects disabled
     */
    public function withoutRedirects(): self
    {
        return new self(
            $this->timeout,
            $this->maxSize,
            false,
            0,
            $this->userAgent
        );
    }
}
