<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Session;

/**
 * Computes the client fingerprint a session is bound to
 *
 * The fingerprint is a SHA-256 hash over the client attributes selected in
 * SessionConfig. It is stored server-side in the session and compared on
 * every request - a stolen session ID replayed from a different client
 * produces a different fingerprint and is rejected.
 *
 * No secret is involved: the fingerprint never leaves the server, so
 * there is nothing for an attacker to forge offline.
 */
final readonly class SessionFingerprint
{
    /**
     * Domain separator, versioned for future algorithm changes
     */
    private const string DOMAIN_PREFIX = 'zappzarapp-session-fingerprint-v1';

    public function __construct(
        private SessionConfig $config,
    ) {
    }

    /**
     * Compute the fingerprint for a client context
     *
     * @return string 64-character lowercase hex SHA-256 digest
     */
    public function compute(SessionContext $context): string
    {
        $parts = [self::DOMAIN_PREFIX];

        if ($this->config->bindIpAddress) {
            $parts[] = 'ip:' . $context->ipAddress;
        }

        if ($this->config->bindUserAgent) {
            $parts[] = 'ua:' . $context->userAgent;
        }

        return hash('sha256', implode("\x00", $parts));
    }
}
