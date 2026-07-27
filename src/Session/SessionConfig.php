<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Session;

use Zappzarapp\Security\Cookie\SameSitePolicy;
use Zappzarapp\Security\Session\Exception\SessionConfigurationException;

/**
 * Session security configuration with secure defaults
 *
 * Defaults, and why:
 *
 * - Cookie name `__Host-session`: the __Host- prefix makes browsers enforce
 *   Secure, Path=/ and no Domain attribute, preventing subdomain cookie
 *   injection. Requires HTTPS - override the name and secureCookie for
 *   plain-HTTP development environments only.
 * - Secure + HttpOnly cookie, SameSite=Lax: not readable from JavaScript,
 *   not sent on cross-site subrequests.
 * - User-Agent binding on, IP binding off: a stolen session ID is rejected
 *   when replayed from a different client, while mobile users switching
 *   networks (new IP) stay logged in. Enable IP binding for high-security
 *   applications with stable client networks.
 * - 30 minutes idle timeout, 12 hours absolute timeout.
 */
final readonly class SessionConfig
{
    /**
     * Allowed cookie name format (RFC 6265 token subset)
     */
    private const string COOKIE_NAME_PATTERN = '/^[A-Za-z0-9_\-.]+\z/';

    /**
     * @param int $idleTimeout Seconds of inactivity before the session expires
     * @param int $absoluteTimeout Seconds after creation before the session expires regardless of activity
     * @param bool $bindUserAgent Bind the session to the client's User-Agent header
     * @param bool $bindIpAddress Bind the session to the client's IP address
     * @param bool $secureCookie Send the session cookie over HTTPS only
     * @param SameSitePolicy $sameSite SameSite attribute for the session cookie
     * @param string $cookieName Session cookie name
     *
     * @throws SessionConfigurationException If timeouts or the cookie name are invalid
     */
    public function __construct(
        public int $idleTimeout = 1800,
        public int $absoluteTimeout = 43200,
        public bool $bindUserAgent = true,
        public bool $bindIpAddress = false,
        public bool $secureCookie = true,
        public SameSitePolicy $sameSite = SameSitePolicy::LAX,
        public string $cookieName = '__Host-session',
    ) {
        if ($this->idleTimeout < 1) {
            throw SessionConfigurationException::nonPositiveTimeout('idle', $this->idleTimeout);
        }

        if ($this->absoluteTimeout < 1) {
            throw SessionConfigurationException::nonPositiveTimeout('absolute', $this->absoluteTimeout);
        }

        if ($this->idleTimeout > $this->absoluteTimeout) {
            throw SessionConfigurationException::idleExceedsAbsolute(
                $this->idleTimeout,
                $this->absoluteTimeout
            );
        }

        if (preg_match(self::COOKIE_NAME_PATTERN, $this->cookieName) !== 1) {
            throw SessionConfigurationException::invalidCookieName();
        }
    }

    /**
     * Strict configuration for high-security applications
     *
     * Adds IP binding, SameSite=Strict, and shorter timeouts
     * (15 minutes idle, 4 hours absolute).
     */
    public static function strict(): self
    {
        return new self(
            idleTimeout: 900,
            absoluteTimeout: 14400,
            bindIpAddress: true,
            sameSite: SameSitePolicy::STRICT,
        );
    }
}
