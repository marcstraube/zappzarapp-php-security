<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Cookie;

use Zappzarapp\Security\Cookie\Exception\InvalidCookieOptionsException;

/**
 * Immutable cookie options
 *
 * Encapsulates all cookie attributes with secure defaults.
 */
final readonly class CookieOptions
{
    /**
     * @param int $expires Expiration timestamp (0 = session cookie)
     * @param string $path Cookie path
     * @param string $domain Cookie domain
     * @param bool $secure Only send over HTTPS
     * @param bool $httpOnly Prevent JavaScript access
     * @param SameSitePolicy $sameSite SameSite attribute
     */
    public function __construct(
        public int $expires = 0,
        public string $path = '/',
        public string $domain = '',
        public bool $secure = true,
        public bool $httpOnly = true,
        public SameSitePolicy $sameSite = SameSitePolicy::STRICT,
    ) {
    }

    /**
     * Create with custom expiration
     */
    public function withExpires(int $expires): self
    {
        return new self(
            $expires,
            $this->path,
            $this->domain,
            $this->secure,
            $this->httpOnly,
            $this->sameSite
        );
    }

    /**
     * Create with expiration relative to now
     */
    public function withMaxAge(int $seconds): self
    {
        return $this->withExpires(time() + $seconds);
    }

    /**
     * Create with custom path
     *
     * @throws InvalidCookieOptionsException If path contains invalid characters (header injection prevention)
     */
    public function withPath(string $path): self
    {
        // Validate path to prevent HTTP header injection
        if (preg_match('/[\r\n;,\x00]/', $path) === 1) {
            throw InvalidCookieOptionsException::invalidPath($path);
        }

        return new self(
            $this->expires,
            $path,
            $this->domain,
            $this->secure,
            $this->httpOnly,
            $this->sameSite
        );
    }

    /**
     * Create with custom domain
     *
     * @throws InvalidCookieOptionsException If domain contains invalid characters (header injection prevention)
     */
    public function withDomain(string $domain): self
    {
        // Validate domain to prevent HTTP header injection
        // These characters can be used to inject additional headers or
        // terminate the current header and inject new ones
        if (preg_match('/[\r\n;,\x00]/', $domain) === 1) {
            throw InvalidCookieOptionsException::invalidDomain($domain);
        }

        return new self(
            $this->expires,
            $this->path,
            $domain,
            $this->secure,
            $this->httpOnly,
            $this->sameSite
        );
    }

    /**
     * Create with Secure flag enabled
     */
    public function withSecure(): self
    {
        return new self(
            $this->expires,
            $this->path,
            $this->domain,
            true,
            $this->httpOnly,
            $this->sameSite
        );
    }

    /**
     * Create with Secure flag disabled
     */
    public function withoutSecure(): self
    {
        return new self(
            $this->expires,
            $this->path,
            $this->domain,
            false,
            $this->httpOnly,
            $this->sameSite
        );
    }

    /**
     * Create with HttpOnly flag enabled
     */
    public function withHttpOnly(): self
    {
        return new self(
            $this->expires,
            $this->path,
            $this->domain,
            $this->secure,
            true,
            $this->sameSite
        );
    }

    /**
     * Create with HttpOnly flag disabled
     */
    public function withoutHttpOnly(): self
    {
        return new self(
            $this->expires,
            $this->path,
            $this->domain,
            $this->secure,
            false,
            $this->sameSite
        );
    }

    /**
     * Create with custom SameSite policy
     *
     * @throws InvalidCookieOptionsException If SameSite=None is used without Secure flag
     */
    public function withSameSite(SameSitePolicy $sameSite): self
    {
        // SameSite=None requires Secure flag (RFC 6265bis, enforced by modern browsers)
        if ($sameSite === SameSitePolicy::NONE && !$this->secure) {
            throw InvalidCookieOptionsException::sameSiteNoneRequiresSecure();
        }

        return new self(
            $this->expires,
            $this->path,
            $this->domain,
            $this->secure,
            $this->httpOnly,
            $sameSite
        );
    }

    /**
     * Create with SameSite=None (automatically enables Secure)
     *
     * Use for cross-site cookie scenarios (OAuth, embedded iframes).
     * Automatically sets Secure=true as required by RFC 6265bis.
     */
    public function withSameSiteNone(): self
    {
        return new self(
            $this->expires,
            $this->path,
            $this->domain,
            true, // Secure required for SameSite=None
            $this->httpOnly,
            SameSitePolicy::NONE
        );
    }

    /**
     * Convert to array for setcookie()
     *
     * @return array{expires: int, path: string, domain: string, secure: bool, httponly: bool, samesite: 'Lax'|'None'|'Strict'}
     */
    public function toArray(): array
    {
        return [
            'expires'  => $this->expires,
            'path'     => $this->path,
            'domain'   => $this->domain,
            'secure'   => $this->secure,
            'httponly' => $this->httpOnly,
            'samesite' => $this->sameSite->attributeValue(),
        ];
    }

    /**
     * Create strict options (most secure)
     *
     * - Secure: true
     * - HttpOnly: true
     * - SameSite: Strict
     */
    public static function strict(): self
    {
        return new self();
    }

    /**
     * Create lax options (for links from external sites)
     */
    public static function lax(): self
    {
        return new self(sameSite: SameSitePolicy::LAX);
    }

    /**
     * Create options for JavaScript-accessible cookies
     *
     * Use sparingly - only when JS needs to read the cookie.
     */
    public static function jsAccessible(): self
    {
        return new self(httpOnly: false);
    }

    /**
     * Create options for development (not secure)
     *
     * WARNING: Creates cookies without Secure flag. Only use for local HTTP development.
     * Do NOT use in production - cookies will be transmitted over unencrypted connections.
     */
    public static function development(): self
    {
        // Warn if used in apparent production environment
        if (self::appearsToBeHttps()) {
            trigger_error(
                'CookieOptions::development() used in HTTPS context. '
                . 'Use CookieOptions::secure() or default() for production.',
                E_USER_WARNING
            );
        }

        return new self(
            secure: false,
            sameSite: SameSitePolicy::LAX
        );
    }

    /**
     * Check if current request appears to be HTTPS
     */
    private static function appearsToBeHttps(): bool
    {
        // Direct HTTPS
        if (($_SERVER['HTTPS'] ?? '') === 'on') {
            return true;
        }

        // Behind reverse proxy
        if (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') {
            return true;
        }

        // Standard HTTPS port
        return ($_SERVER['SERVER_PORT'] ?? '') === '443';
    }
}
