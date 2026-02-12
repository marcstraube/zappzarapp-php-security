<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Hsts;

use Zappzarapp\Security\Headers\Exception\InvalidHeaderValueException;

/**
 * HTTP Strict Transport Security (HSTS) Configuration
 *
 * Immutable value object for HSTS header configuration.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
 */
final readonly class HstsConfig
{
    /**
     * Minimum max-age for HSTS preload list submission (1 year)
     */
    public const int PRELOAD_MIN_MAX_AGE = 31536000;

    /**
     * Recommended max-age for production (2 years)
     */
    public const int RECOMMENDED_MAX_AGE = 63072000;

    /**
     * @param int $maxAge Time in seconds the browser should remember HSTS
     * @param bool $includeSubDomains Apply HSTS to all subdomains
     * @param bool $preload Indicate consent for HSTS preload list inclusion
     *
     * @throws InvalidHeaderValueException If configuration is invalid
     */
    public function __construct(
        public int $maxAge = self::RECOMMENDED_MAX_AGE,
        public bool $includeSubDomains = true,
        public bool $preload = false,
    ) {
        if ($this->maxAge < 0) {
            throw InvalidHeaderValueException::invalidMaxAge($this->maxAge);
        }

        if ($this->preload && !$this->includeSubDomains) {
            throw InvalidHeaderValueException::preloadRequiresIncludeSubDomains();
        }

        if ($this->preload && $this->maxAge < self::PRELOAD_MIN_MAX_AGE) {
            throw InvalidHeaderValueException::preloadRequiresMinMaxAge(
                self::PRELOAD_MIN_MAX_AGE,
                $this->maxAge
            );
        }
    }

    /**
     * Create with custom max-age
     *
     * @throws InvalidHeaderValueException If maxAge is negative
     */
    public function withMaxAge(int $maxAge): self
    {
        return new self($maxAge, $this->includeSubDomains, $this->preload);
    }

    /**
     * Create with includeSubDomains enabled
     */
    public function withIncludeSubDomains(): self
    {
        return new self($this->maxAge, true, $this->preload);
    }

    /**
     * Create with includeSubDomains disabled
     *
     * @throws InvalidHeaderValueException If preload is enabled
     */
    public function withoutIncludeSubDomains(): self
    {
        return new self($this->maxAge, false, $this->preload);
    }

    /**
     * Create with preload enabled
     *
     * @throws InvalidHeaderValueException If includeSubDomains is disabled or max-age too low
     */
    public function withPreload(): self
    {
        return new self($this->maxAge, $this->includeSubDomains, true);
    }

    /**
     * Create with preload disabled
     */
    public function withoutPreload(): self
    {
        return new self($this->maxAge, $this->includeSubDomains, false);
    }

    /**
     * Build header value string
     */
    public function headerValue(): string
    {
        $value = 'max-age=' . $this->maxAge;

        if ($this->includeSubDomains) {
            $value .= '; includeSubDomains';
        }

        if ($this->preload) {
            $value .= '; preload';
        }

        return $value;
    }

    /**
     * Create strict configuration (recommended for production)
     *
     * - 2 years max-age
     * - includeSubDomains enabled
     * - preload disabled (opt-in)
     */
    public static function strict(): self
    {
        return new self(
            maxAge: self::RECOMMENDED_MAX_AGE,
            includeSubDomains: true,
            preload: false
        );
    }

    /**
     * Create preload-ready configuration
     *
     * - 2 years max-age (meets preload requirement)
     * - includeSubDomains enabled (required for preload)
     * - preload enabled
     *
     * Warning: Only use if you're ready to commit to HTTPS permanently.
     * Removal from preload list can take months.
     */
    public static function preload(): self
    {
        return new self(
            maxAge: self::RECOMMENDED_MAX_AGE,
            includeSubDomains: true,
            preload: true
        );
    }

    /**
     * Create short max-age configuration for testing
     *
     * - 5 minutes max-age
     * - includeSubDomains disabled
     * - preload disabled
     */
    public static function testing(): self
    {
        return new self(
            maxAge: 300,
            includeSubDomains: false,
            preload: false
        );
    }

    /**
     * Create configuration to effectively disable HSTS
     *
     * - 0 seconds max-age (browser will forget HSTS immediately)
     * - includeSubDomains disabled
     * - preload disabled
     */
    public static function disabled(): self
    {
        return new self(
            maxAge: 0,
            includeSubDomains: false,
            preload: false
        );
    }
}
