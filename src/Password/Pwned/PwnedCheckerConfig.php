<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Pwned;

use InvalidArgumentException;

/**
 * Configuration for HIBP Pwned Passwords checker
 */
final readonly class PwnedCheckerConfig
{
    /**
     * HIBP Pwned Passwords API endpoint
     */
    public const string DEFAULT_API_URL = 'https://api.pwnedpasswords.com/range/';

    /**
     * Minimum occurrences to consider password compromised
     */
    public const int DEFAULT_MIN_OCCURRENCES = 1;

    /**
     * Count returned when fail-closed mode is active and API is unavailable
     */
    public const int FAIL_CLOSED_COUNT = PHP_INT_MAX;

    /**
     * @throws InvalidArgumentException If apiUrl does not use HTTPS scheme
     */
    public function __construct(
        public string $apiUrl = self::DEFAULT_API_URL,
        public int $minOccurrences = self::DEFAULT_MIN_OCCURRENCES,
        public int $timeout = 5,
        public bool $throwOnError = false,
        public bool $failClosed = true,
    ) {
        $this->validateApiUrl($apiUrl);
    }

    /**
     * Validate API URL for security (SSRF prevention)
     *
     * @throws InvalidArgumentException If URL is not a valid HTTPS URL
     */
    private function validateApiUrl(string $url): void
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);

        if ($scheme !== 'https') {
            throw new InvalidArgumentException(
                'API URL must use HTTPS scheme. Got: ' . ($scheme ?? 'null')
            );
        }
    }

    /**
     * Create with custom API URL
     */
    public function withApiUrl(string $apiUrl): self
    {
        return new self($apiUrl, $this->minOccurrences, $this->timeout, $this->throwOnError, $this->failClosed);
    }

    /**
     * Create with custom minimum occurrences
     */
    public function withMinOccurrences(int $minOccurrences): self
    {
        return new self($this->apiUrl, $minOccurrences, $this->timeout, $this->throwOnError, $this->failClosed);
    }

    /**
     * Create with custom timeout
     */
    public function withTimeout(int $timeout): self
    {
        return new self($this->apiUrl, $this->minOccurrences, $timeout, $this->throwOnError, $this->failClosed);
    }

    /**
     * Create with throw on error enabled
     */
    public function withThrowOnError(): self
    {
        return new self($this->apiUrl, $this->minOccurrences, $this->timeout, true, $this->failClosed);
    }

    /**
     * Create with throw on error disabled
     */
    public function withoutThrowOnError(): self
    {
        return new self($this->apiUrl, $this->minOccurrences, $this->timeout, false, $this->failClosed);
    }

    /**
     * Create with fail-closed mode enabled (default behavior)
     *
     * When enabled, API failures return FAIL_CLOSED_COUNT instead of 0,
     * treating the password as compromised when verification is impossible.
     * This is the recommended setting for production environments.
     */
    public function withFailClosed(): self
    {
        return new self($this->apiUrl, $this->minOccurrences, $this->timeout, $this->throwOnError, true);
    }

    /**
     * Create with fail-closed mode disabled (fail-open behavior)
     *
     * Use only for development/testing where API availability issues
     * should not block password validation.
     */
    public function withoutFailClosed(): self
    {
        return new self($this->apiUrl, $this->minOccurrences, $this->timeout, $this->throwOnError, false);
    }

    /**
     * Create configuration for production use
     *
     * - Fail-closed: enabled (API failures reject passwords)
     * - Throw on error: disabled (graceful degradation)
     * - Default timeout: 5 seconds
     */
    public static function production(): self
    {
        return new self(throwOnError: false, failClosed: true);
    }

    /**
     * Create configuration for development/testing
     *
     * - Fail-closed: disabled (API failures allow passwords)
     * - Throw on error: disabled
     * - Default timeout: 5 seconds
     */
    public static function development(): self
    {
        return new self(throwOnError: false, failClosed: false);
    }
}
