<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Session;

use Psr\Clock\ClockInterface;

/**
 * Runtime session security checks: fingerprint binding and timeouts
 *
 * Operates on the session data array directly (usually $_SESSION), keeping
 * the guard free of global session state. The caller remains responsible
 * for the session lifecycle (session_start(), session_regenerate_id(),
 * session_destroy()).
 *
 * ## Usage
 *
 * ```php
 * $config = new SessionConfig();
 * $guard  = new SessionGuard($config);
 *
 * session_start();
 * $context = SessionContext::fromGlobals();
 *
 * $result = $guard->validate($_SESSION, $context);
 * if (!$result->isValid()) {
 *     session_unset();
 *     session_destroy();
 *     // require re-authentication
 * }
 *
 * // After login or any privilege change: prevent session fixation
 * session_regenerate_id(true);
 * $guard->initialize($_SESSION, $context);
 * ```
 */
final readonly class SessionGuard
{
    /**
     * Session key holding the security metadata
     */
    private const string METADATA_KEY = '_zappzarapp_session_security';

    private SessionFingerprint $fingerprint;

    /**
     * @param SessionConfig $config The session security configuration
     * @param ClockInterface|null $clock Optional PSR-20 clock (system time when null)
     */
    public function __construct(
        private SessionConfig $config = new SessionConfig(),
        private ?ClockInterface $clock = null,
    ) {
        $this->fingerprint = new SessionFingerprint($this->config);
    }

    /**
     * Bind security metadata to the session
     *
     * Call after session_start() for a fresh session, and again after every
     * session_regenerate_id() on login or privilege change (session
     * fixation protection resets the clock and re-binds the fingerprint).
     *
     * @param array<array-key, mixed> $session The session data (usually $_SESSION)
     */
    public function initialize(array &$session, SessionContext $context): void
    {
        $now = $this->now();

        $session[self::METADATA_KEY] = [
            'created_at'    => $now,
            'last_activity' => $now,
            'fingerprint'   => $this->fingerprint->compute($context),
        ];
    }

    /**
     * Validate the session against fingerprint and timeout rules
     *
     * On success, the idle timer is refreshed. On any failure the caller
     * should destroy the session - the metadata is left untouched for
     * logging purposes.
     *
     * @param array<array-key, mixed> $session The session data (usually $_SESSION)
     */
    public function validate(array &$session, SessionContext $context): SessionValidationResult
    {
        $metadata = $this->metadata($session);

        if ($metadata === null) {
            return SessionValidationResult::UNINITIALIZED;
        }

        if (!hash_equals($metadata['fingerprint'], $this->fingerprint->compute($context))) {
            return SessionValidationResult::FINGERPRINT_MISMATCH;
        }

        $now = $this->now();

        if ($now - $metadata['created_at'] > $this->config->absoluteTimeout) {
            return SessionValidationResult::ABSOLUTE_TIMEOUT_EXCEEDED;
        }

        if ($now - $metadata['last_activity'] > $this->config->idleTimeout) {
            return SessionValidationResult::IDLE_TIMEOUT_EXCEEDED;
        }

        $metadata['last_activity']   = $now;
        $session[self::METADATA_KEY] = $metadata;

        return SessionValidationResult::VALID;
    }

    /**
     * Current Unix timestamp from the injected clock or system time
     */
    private function now(): int
    {
        if (!$this->clock instanceof ClockInterface) {
            return time();
        }

        return $this->clock->now()->getTimestamp();
    }

    /**
     * Extract and type-check the security metadata
     *
     * @param array<array-key, mixed> $session
     *
     * @return array{created_at: int, last_activity: int, fingerprint: string}|null
     */
    private function metadata(array $session): ?array
    {
        $metadata = $session[self::METADATA_KEY] ?? null;

        if (!is_array($metadata)) {
            return null;
        }

        $createdAt    = $metadata['created_at'] ?? null;
        $lastActivity = $metadata['last_activity'] ?? null;
        $fingerprint  = $metadata['fingerprint'] ?? null;

        if (!is_int($createdAt) || !is_int($lastActivity) || !is_string($fingerprint)) {
            return null;
        }

        return [
            'created_at'    => $createdAt,
            'last_activity' => $lastActivity,
            'fingerprint'   => $fingerprint,
        ];
    }
}
