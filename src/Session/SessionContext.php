<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Session;

/**
 * Client attributes a session can be bound to
 *
 * Which attributes are actually used is controlled by SessionConfig
 * (bindUserAgent / bindIpAddress).
 */
final readonly class SessionContext
{
    public function __construct(
        public string $ipAddress = '',
        public string $userAgent = '',
    ) {
    }

    /**
     * Create from PHP superglobals ($_SERVER)
     *
     * Note: REMOTE_ADDR is the direct peer. Behind a reverse proxy this is
     * the proxy's address - resolve the real client IP from your trusted
     * proxy configuration and use the constructor instead.
     */
    public static function fromGlobals(): self
    {
        $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        return new self(
            is_string($ipAddress) ? $ipAddress : '',
            is_string($userAgent) ? $userAgent : ''
        );
    }
}
