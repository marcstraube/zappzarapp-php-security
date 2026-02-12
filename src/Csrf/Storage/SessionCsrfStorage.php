<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Storage;

use Override;
use RuntimeException;

/**
 * Session-based CSRF token storage
 *
 * Stores tokens in PHP session. Requires an active session.
 */
final readonly class SessionCsrfStorage implements CsrfStorageInterface
{
    private const string SESSION_KEY = '_csrf_tokens';

    public function __construct(
        private string $sessionKey = self::SESSION_KEY,
    ) {
    }

    #[Override]
    public function store(string $key, string $token, ?int $ttl = null): void
    {
        $this->ensureSessionStarted();

        $data = [
            'token'   => $token,
            'expires' => $ttl !== null ? time() + $ttl : null,
        ];

        /** @psalm-suppress MixedArrayAssignment */
        $_SESSION[$this->sessionKey][$key] = $data;
    }

    #[Override]
    public function retrieve(string $key): ?string
    {
        $this->ensureSessionStarted();

        /** @psalm-suppress MixedArrayAccess */
        if (!isset($_SESSION[$this->sessionKey][$key])) {
            return null;
        }

        /**
         * @psalm-suppress MixedArrayAccess
         * @var array{token: string, expires: int|null} $data
         */
        $data = $_SESSION[$this->sessionKey][$key];

        // Check expiration
        if ($data['expires'] !== null && $data['expires'] < time()) {
            /** @psalm-suppress MixedArrayAccess */
            unset($_SESSION[$this->sessionKey][$key]);

            return null;
        }

        return $data['token'];
    }

    #[Override]
    public function remove(string $key): void
    {
        $this->ensureSessionStarted();

        /** @psalm-suppress MixedArrayAccess */
        unset($_SESSION[$this->sessionKey][$key]);
    }

    #[Override]
    public function has(string $key): bool
    {
        return $this->retrieve($key) !== null;
    }

    #[Override]
    public function clear(): void
    {
        $this->ensureSessionStarted();

        $_SESSION[$this->sessionKey] = [];
    }

    /**
     * Ensure session is active
     *
     * Does NOT start the session automatically - this is the application's
     * responsibility. Implicit session_start() is a security risk because:
     * - Session settings (secure, httponly, etc.) should be configured first
     * - Session ID regeneration may be needed before use
     * - The application should control when sessions are created
     *
     * @throws RuntimeException If session is not active
     */
    private function ensureSessionStarted(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        // @codeCoverageIgnoreStart - Requires PHP compiled with --disable-session
        if (session_status() === PHP_SESSION_DISABLED) {
            throw new RuntimeException('Sessions are disabled');
        }

        // @codeCoverageIgnoreEnd

        throw new RuntimeException(
            'Session must be started before using SessionCsrfStorage. '
            . 'Configure session security settings first, then call session_start(). '
            . 'Example: ini_set("session.cookie_secure", "1"); '
            . 'ini_set("session.cookie_httponly", "1"); '
            . 'ini_set("session.cookie_samesite", "Strict"); '
            . 'session_start();'
        );
    }
}
