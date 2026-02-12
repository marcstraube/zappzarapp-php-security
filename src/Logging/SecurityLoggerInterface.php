<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.0 interface, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Logging;

use Random\RandomException;
use Stringable;

/**
 * Security audit logger interface
 *
 * PSR-3 compatible interface for security event logging.
 * Any PSR-3 LoggerInterface implementation can be used directly.
 */
interface SecurityLoggerInterface
{
    /**
     * Log a security warning event
     *
     * Use for: rate limit warnings, policy violations
     *
     * @param string|Stringable $message The log message
     * @param array<string, mixed> $context Additional context
     */
    public function warning(string|Stringable $message, array $context = []): void;

    /**
     * Log a security alert event
     *
     * Use for: rate limit exceeded, CSRF validation failure
     *
     * @param string|Stringable $message The log message
     * @param array<string, mixed> $context Additional context
     */
    public function alert(string|Stringable $message, array $context = []): void;

    /**
     * Log a critical security event
     *
     * Use for: compromised password detected, path traversal attempt, XSS blocked
     *
     * @param string|Stringable $message The log message
     * @param array<string, mixed> $context Additional context
     */
    public function critical(string|Stringable $message, array $context = []): void;

    /**
     * Log a structured security event
     *
     * @param SecurityEvent $event The security event to log
     *
     * @throws RandomException If correlation ID generation fails
     */
    public function securityEvent(SecurityEvent $event): void;
}
