<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Cookie;

use Zappzarapp\Security\Cookie\Exception\InvalidCookieNameException;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieValueException;

/**
 * Fluent cookie builder
 *
 * ## Usage
 *
 * ```php
 * $cookie = CookieBuilder::create('session_id', $id)
 *     ->maxAge(3600)
 *     ->path('/app')
 *     ->sameSite(SameSitePolicy::LAX)
 *     ->build();
 * ```
 */
final class CookieBuilder
{
    private int $expires             = 0;

    private string $path             = '/';

    private string $domain           = '';

    private bool $secure             = true;

    private bool $httpOnly           = true;

    private SameSitePolicy $sameSite = SameSitePolicy::STRICT;

    public function __construct(private readonly string $name, private string $value = '')
    {
    }

    /**
     * Create a new builder
     */
    public static function create(string $name, string $value = ''): self
    {
        return new self($name, $value);
    }

    /**
     * Set the cookie value
     */
    public function value(string $value): self
    {
        $this->value = $value;

        return $this;
    }

    /**
     * Set expiration timestamp
     */
    public function expires(int $timestamp): self
    {
        $this->expires = $timestamp;

        return $this;
    }

    /**
     * Set max-age (seconds from now)
     */
    public function maxAge(int $seconds): self
    {
        $this->expires = time() + $seconds;

        return $this;
    }

    /**
     * Set cookie path
     */
    public function path(string $path): self
    {
        $this->path = $path;

        return $this;
    }

    /**
     * Set cookie domain
     */
    public function domain(string $domain): self
    {
        $this->domain = $domain;

        return $this;
    }

    /**
     * Enable/disable Secure flag
     */
    public function secure(bool $secure = true): self
    {
        $this->secure = $secure;

        return $this;
    }

    /**
     * Enable/disable HttpOnly flag
     */
    public function httpOnly(bool $httpOnly = true): self
    {
        $this->httpOnly = $httpOnly;

        return $this;
    }

    /**
     * Set SameSite policy
     */
    public function sameSite(SameSitePolicy $sameSite): self
    {
        $this->sameSite = $sameSite;

        return $this;
    }

    /**
     * Apply strict settings (default)
     */
    public function strict(): self
    {
        $this->secure   = true;
        $this->httpOnly = true;
        $this->sameSite = SameSitePolicy::STRICT;

        return $this;
    }

    /**
     * Apply lax settings
     */
    public function lax(): self
    {
        $this->secure   = true;
        $this->httpOnly = true;
        $this->sameSite = SameSitePolicy::LAX;

        return $this;
    }

    /**
     * Apply development settings (insecure)
     */
    public function development(): self
    {
        $this->secure   = false;
        $this->httpOnly = true;
        $this->sameSite = SameSitePolicy::LAX;

        return $this;
    }

    /**
     * Build the SecureCookie instance
     *
     * @throws InvalidCookieNameException If name is invalid
     * @throws InvalidCookieValueException If value is invalid
     */
    public function build(): SecureCookie
    {
        $options = new CookieOptions(
            expires: $this->expires,
            path: $this->path,
            domain: $this->domain,
            secure: $this->secure,
            httpOnly: $this->httpOnly,
            sameSite: $this->sameSite
        );

        return new SecureCookie($this->name, $this->value, $options);
    }

    /**
     * Build and send the cookie
     *
     * @throws InvalidCookieNameException If name is invalid
     * @throws InvalidCookieValueException If value is invalid
     *
     * @return bool True if sent successfully
     */
    public function send(): bool
    {
        return $this->build()->send();
    }
}
