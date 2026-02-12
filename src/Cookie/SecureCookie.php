<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Cookie;

use Zappzarapp\Security\Cookie\Exception\InvalidCookieNameException;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieValueException;

/**
 * Immutable secure cookie value object
 *
 * Represents a cookie with validated name/value and secure defaults.
 *
 * ## Basic Usage
 *
 * ```php
 * $cookie = new SecureCookie('session_id', $sessionId);
 * $cookie->send(); // Sets cookie with secure defaults
 * ```
 *
 * ## With Custom Options
 *
 * ```php
 * $cookie = new SecureCookie('prefs', json_encode($prefs))
 *     ->withOptions(CookieOptions::lax()->withMaxAge(86400 * 30));
 * ```
 */
final readonly class SecureCookie
{
    /**
     * @param string $name Cookie name
     * @param string $value Cookie value
     * @param CookieOptions $options Cookie options
     *
     * @throws InvalidCookieNameException If name is invalid or prefix constraints violated
     * @throws InvalidCookieValueException If value is invalid
     */
    public function __construct(
        public string $name,
        public string $value,
        public CookieOptions $options = new CookieOptions(),
    ) {
        $validator = new CookieValidator();
        $validator->validateName($this->name);
        $validator->validateValue($this->value);
        $validator->validatePrefixConstraints($this->name, $this->options);
    }

    /**
     * Create with custom value
     *
     * @throws InvalidCookieValueException If value is invalid
     */
    public function withValue(string $value): self
    {
        return new self($this->name, $value, $this->options);
    }

    /**
     * Create with custom options
     */
    public function withOptions(CookieOptions $options): self
    {
        return new self($this->name, $this->value, $options);
    }

    /**
     * Create with expiration relative to now
     */
    public function withMaxAge(int $seconds): self
    {
        return $this->withOptions($this->options->withMaxAge($seconds));
    }

    /**
     * Create with custom path
     */
    public function withPath(string $path): self
    {
        return $this->withOptions($this->options->withPath($path));
    }

    /**
     * Create with custom domain
     */
    public function withDomain(string $domain): self
    {
        return $this->withOptions($this->options->withDomain($domain));
    }

    /**
     * Send the cookie using setcookie()
     *
     * @return bool True if sent successfully, false if headers already sent
     */
    public function send(): bool
    {
        if (headers_sent()) {
            return false;
        }

        return setcookie($this->name, $this->value, $this->options->toArray());
    }

    /**
     * Build Set-Cookie header value
     */
    public function headerValue(): string
    {
        $parts = [
            $this->name . '=' . rawurlencode($this->value),
        ];

        if ($this->options->expires > 0) {
            $parts[] = 'Expires=' . gmdate('D, d M Y H:i:s T', $this->options->expires);
            $parts[] = 'Max-Age=' . max(0, $this->options->expires - time());
        }

        if ($this->options->path !== '') {
            $parts[] = 'Path=' . $this->options->path;
        }

        if ($this->options->domain !== '') {
            $parts[] = 'Domain=' . $this->options->domain;
        }

        if ($this->options->secure) {
            $parts[] = 'Secure';
        }

        if ($this->options->httpOnly) {
            $parts[] = 'HttpOnly';
        }

        $parts[] = 'SameSite=' . $this->options->sameSite->attributeValue();

        return implode('; ', $parts);
    }

    /**
     * Create a cookie for deletion
     *
     * Sets expires to past to trigger browser deletion.
     */
    public function toDelete(): self
    {
        return new self(
            $this->name,
            '',
            $this->options->withExpires(1) // 1970-01-01
        );
    }

    /**
     * Create a session cookie (strict, HTTP-only, session lifetime)
     *
     * @throws InvalidCookieNameException If name is invalid
     * @throws InvalidCookieValueException If value is invalid
     */
    public static function session(string $name, string $value): self
    {
        return new self($name, $value, CookieOptions::strict());
    }

    /**
     * Create a persistent cookie with max-age
     *
     * @param int $maxAge Max age in seconds
     *
     * @throws InvalidCookieNameException If name is invalid
     * @throws InvalidCookieValueException If value is invalid
     */
    public static function persistent(string $name, string $value, int $maxAge): self
    {
        return new self(
            $name,
            $value,
            CookieOptions::strict()->withMaxAge($maxAge)
        );
    }
}
