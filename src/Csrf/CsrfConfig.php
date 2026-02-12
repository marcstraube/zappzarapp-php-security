<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf;

/**
 * CSRF protection configuration
 */
final readonly class CsrfConfig
{
    /**
     * Default token TTL (2 hours)
     */
    public const int DEFAULT_TTL = 7200;

    /**
     * Default form field name
     */
    public const string DEFAULT_FIELD_NAME = '_csrf_token';

    /**
     * Default header name
     */
    public const string DEFAULT_HEADER_NAME = 'X-CSRF-Token';

    /**
     * Default cookie name for double submit
     */
    public const string DEFAULT_COOKIE_NAME = 'csrf_token';

    /**
     * @param string $fieldName Form field name for the token
     * @param string $headerName HTTP header name for the token
     * @param string $cookieName Cookie name for double submit pattern
     * @param int $ttl Token time-to-live in seconds
     * @param bool $rotateOnValidation Generate new token after successful validation
     * @param bool $singleUse Token can only be used once
     */
    public function __construct(
        public string $fieldName = self::DEFAULT_FIELD_NAME,
        public string $headerName = self::DEFAULT_HEADER_NAME,
        public string $cookieName = self::DEFAULT_COOKIE_NAME,
        public int $ttl = self::DEFAULT_TTL,
        public bool $rotateOnValidation = false,
        public bool $singleUse = false,
    ) {
    }

    /**
     * Create with custom field name
     */
    public function withFieldName(string $fieldName): self
    {
        return new self(
            $fieldName,
            $this->headerName,
            $this->cookieName,
            $this->ttl,
            $this->rotateOnValidation,
            $this->singleUse
        );
    }

    /**
     * Create with custom header name
     */
    public function withHeaderName(string $headerName): self
    {
        return new self(
            $this->fieldName,
            $headerName,
            $this->cookieName,
            $this->ttl,
            $this->rotateOnValidation,
            $this->singleUse
        );
    }

    /**
     * Create with custom cookie name
     */
    public function withCookieName(string $cookieName): self
    {
        return new self(
            $this->fieldName,
            $this->headerName,
            $cookieName,
            $this->ttl,
            $this->rotateOnValidation,
            $this->singleUse
        );
    }

    /**
     * Create with custom TTL
     */
    public function withTtl(int $ttl): self
    {
        return new self(
            $this->fieldName,
            $this->headerName,
            $this->cookieName,
            $ttl,
            $this->rotateOnValidation,
            $this->singleUse
        );
    }

    /**
     * Create with rotation on validation enabled
     */
    public function withRotateOnValidation(): self
    {
        return new self(
            $this->fieldName,
            $this->headerName,
            $this->cookieName,
            $this->ttl,
            true,
            $this->singleUse
        );
    }

    /**
     * Create with rotation on validation disabled
     */
    public function withoutRotateOnValidation(): self
    {
        return new self(
            $this->fieldName,
            $this->headerName,
            $this->cookieName,
            $this->ttl,
            false,
            $this->singleUse
        );
    }

    /**
     * Create with single-use tokens enabled
     */
    public function withSingleUse(): self
    {
        return new self(
            $this->fieldName,
            $this->headerName,
            $this->cookieName,
            $this->ttl,
            $this->rotateOnValidation,
            true
        );
    }

    /**
     * Create with single-use tokens disabled
     */
    public function withoutSingleUse(): self
    {
        return new self(
            $this->fieldName,
            $this->headerName,
            $this->cookieName,
            $this->ttl,
            $this->rotateOnValidation,
            false
        );
    }

    /**
     * Create strict configuration (single-use, shorter TTL)
     */
    public static function strict(): self
    {
        return new self(
            ttl: 1800, // 30 minutes
            singleUse: true
        );
    }

    /**
     * Create default configuration
     */
    public static function default(): self
    {
        return new self();
    }
}
