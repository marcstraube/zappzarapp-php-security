<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Logging;

use Override;
use Psr\Log\LoggerInterface;
use Random\RandomException;
use Stringable;

/**
 * Security audit logger implementation
 *
 * Wraps a PSR-3 logger and adds structured security event logging.
 * Automatically enriches log context with correlation IDs and timestamps.
 *
 * ## Usage
 *
 * ```php
 * $auditLogger = new SecurityAuditLogger($psrLogger);
 *
 * // Simple logging
 * $auditLogger->alert('CSRF validation failed', ['ip' => $ip]);
 *
 * // Structured event logging
 * $event = SecurityEvent::rateLimitExceeded($identifier, $limit, $retryAfter);
 * $auditLogger->securityEvent($event);
 * ```
 *
 * ## PSR-3 Logger Requirements
 *
 * **IMPORTANT:** This class delegates all logging to the injected PSR-3 logger.
 * The underlying logger is responsible for proper output encoding.
 *
 * **Recommended configuration:**
 * - Use a JSON formatter (e.g., Monolog's JsonFormatter) which automatically
 *   escapes newlines, preventing log injection/forging attacks
 * - Avoid line-based text formatters in security-sensitive contexts
 * - Configure proper log rotation and access controls
 *
 * **Log injection considerations:**
 * - JSON-based loggers escape `\n` to `\\n`, mitigating log forging
 * - Line-based loggers may be vulnerable if user input contains newlines
 * - Always validate/sanitize user input before including it in log context
 *
 * Example with Monolog (recommended):
 * ```php
 * use Monolog\Logger;
 * use Monolog\Handler\StreamHandler;
 * use Monolog\Formatter\JsonFormatter;
 *
 * $handler = new StreamHandler('security.log');
 * $handler->setFormatter(new JsonFormatter());
 * $logger = new Logger('security', [$handler]);
 *
 * $auditLogger = new SecurityAuditLogger($logger);
 * ```
 */
final readonly class SecurityAuditLogger implements SecurityLoggerInterface
{
    /**
     * Keys that should be automatically redacted from log context
     *
     * @var list<string>
     */
    private const array SENSITIVE_KEYS = [
        'password',
        'passwd',
        'pass',
        'token',
        'secret',
        'api_key',
        'apikey',
        'api-key',
        'credential',
        'credentials',
        'private_key',
        'privatekey',
        'access_token',
        'refresh_token',
        'auth',
        'authorization',
    ];

    /**
     * Patterns for detecting PII in values (not just keys)
     *
     * @var list<string>
     */
    private const array PII_VALUE_PATTERNS = [
        // Email addresses
        '/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/',
        // Credit card numbers (basic pattern, 13-19 digits with optional separators)
        '/\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7}\b/',
        // Phone numbers (international format)
        '/\+?\d{1,4}[\s\-\.]?\(?\d{1,4}\)?[\s\-\.]?\d{1,4}[\s\-\.]?\d{1,9}/',
        // Social Security Numbers (US format)
        '/\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b/',
    ];

    /**
     * Replacement value for redacted sensitive data
     */
    private const string REDACTED = '***REDACTED***';

    /**
     * Maximum number of keys allowed in context (DoS prevention)
     */
    private const int MAX_CONTEXT_KEYS = 50;

    /**
     * Maximum nesting depth for context arrays (DoS prevention)
     */
    private const int MAX_CONTEXT_DEPTH = 5;

    /**
     * Maximum string length for context values (DoS prevention)
     */
    private const int MAX_STRING_LENGTH = 1000;

    /**
     * Placeholder for truncated content
     */
    private const string TRUNCATED = '***TRUNCATED***';

    private string $correlationId;

    /**
     * @param LoggerInterface $logger The underlying PSR-3 logger
     * @param string|null $correlationId Optional correlation ID for all events
     *
     * @throws RandomException If no correlation ID is provided and secure random generation fails
     */
    public function __construct(
        private LoggerInterface $logger,
        ?string $correlationId = null,
    ) {
        $this->correlationId = $correlationId ?? $this->generateCorrelationId();
    }

    /**
     * Create with a specific correlation ID
     *
     * @throws RandomException If the provided correlation ID is used and random generation fails
     */
    public function withCorrelationId(string $correlationId): self
    {
        return new self($this->logger, $correlationId);
    }

    /**
     * Get the current correlation ID
     */
    public function correlationId(): string
    {
        return $this->correlationId;
    }

    #[Override]
    public function warning(string|Stringable $message, array $context = []): void
    {
        $this->logger->warning((string) $message, $this->enrichContext($context));
    }

    #[Override]
    public function alert(string|Stringable $message, array $context = []): void
    {
        $this->logger->alert((string) $message, $this->enrichContext($context));
    }

    #[Override]
    public function critical(string|Stringable $message, array $context = []): void
    {
        $this->logger->critical((string) $message, $this->enrichContext($context));
    }

    #[Override]
    public function securityEvent(SecurityEvent $event): void
    {
        // Use event's correlation ID or fall back to logger's
        $eventWithCorrelation = $event->correlationId !== ''
            ? $event
            : $event->withCorrelationId($this->correlationId);

        $context = $this->enrichContext([
            'event_type'      => $eventWithCorrelation->type->value,
            'correlation_id'  => $eventWithCorrelation->correlationId,
            'event_timestamp' => $eventWithCorrelation->timestamp->format('c'),
            ...$eventWithCorrelation->context,
        ]);

        match ($eventWithCorrelation->severity()) {
            'warning'  => $this->logger->warning($eventWithCorrelation->message(), $context),
            'alert'    => $this->logger->alert($eventWithCorrelation->message(), $context),
            'critical' => $this->logger->critical($eventWithCorrelation->message(), $context),
        };
    }

    /**
     * Enrich context with standard fields and mask sensitive data
     *
     * @param array<string, mixed> $context
     *
     * @return array<string, mixed>
     */
    private function enrichContext(array $context): array
    {
        $truncatedContext = $this->truncateContext($context);
        $maskedContext    = $this->maskSensitiveData($truncatedContext);
        $sanitizedContext = $this->sanitizeForLogInjection($maskedContext);

        return [
            'correlation_id'     => $sanitizedContext['correlation_id'] ?? $this->correlationId,
            'security_component' => 'zappzarapp/security',
            ...$sanitizedContext,
        ];
    }

    /**
     * Sanitize context values to prevent log injection/forging attacks
     *
     * Escapes newline characters that could be used to forge log entries
     * or inject malicious content into log files.
     *
     * @param array<string, mixed> $context
     *
     * @return array<string, mixed>
     */
    private function sanitizeForLogInjection(array $context): array
    {
        $sanitized = [];

        foreach ($context as $key => $value) {
            if (is_string($value)) {
                // Escape newlines to prevent log forging
                $sanitized[$key] = str_replace(
                    ["\r\n", "\r", "\n"],
                    ['\\r\\n', '\\r', '\\n'],
                    $value
                );
            } elseif (is_array($value)) {
                $sanitized[$key] = $this->sanitizeForLogInjection($value);
            } else {
                $sanitized[$key] = $value;
            }
        }

        return $sanitized;
    }

    /**
     * Truncate context to prevent DoS via large payloads
     *
     * Limits the number of keys, nesting depth, and string lengths
     * to prevent memory exhaustion attacks through logging.
     *
     * @param array<string, mixed> $context
     * @param int $depth Current recursion depth
     *
     * @return array<string, mixed>
     */
    private function truncateContext(array $context, int $depth = 0): array
    {
        // Limit nesting depth
        if ($depth >= self::MAX_CONTEXT_DEPTH) {
            return [self::TRUNCATED => 'max depth exceeded'];
        }

        // Limit number of keys
        $keys      = array_keys($context);
        $truncated = count($keys) > self::MAX_CONTEXT_KEYS;
        $keys      = array_slice($keys, 0, self::MAX_CONTEXT_KEYS);

        $result = [];
        foreach ($keys as $key) {
            $value = $context[$key];

            if (is_array($value)) {
                $result[$key] = $this->truncateContext($value, $depth + 1);
            } elseif (is_string($value) && mb_strlen($value, 'UTF-8') > self::MAX_STRING_LENGTH) {
                $result[$key] = mb_substr($value, 0, self::MAX_STRING_LENGTH, 'UTF-8') . '...' . self::TRUNCATED;
            } else {
                $result[$key] = $value;
            }
        }

        if ($truncated) {
            $result[self::TRUNCATED] = sprintf('%d keys omitted', count($context) - self::MAX_CONTEXT_KEYS);
        }

        return $result;
    }

    /**
     * Recursively mask sensitive data in context
     *
     * Automatically redacts:
     * - Values for keys matching sensitive patterns (password, token, secret, api_key, etc.)
     * - Values containing PII patterns (email, phone, credit card, SSN)
     *
     * @param array<string, mixed> $context
     *
     * @return array<string, mixed>
     */
    private function maskSensitiveData(array $context): array
    {
        $masked = [];

        foreach ($context as $key => $value) {
            /** @noinspection PhpCastIsUnnecessaryInspection Array keys can be int|string */
            $lowerKey       = strtolower((string) $key);
            $isSensitiveKey = array_any(self::SENSITIVE_KEYS, fn($sensitiveKey): bool => str_contains($lowerKey, (string) $sensitiveKey));

            if ($isSensitiveKey && $value !== null && $value !== '') {
                $masked[$key] = self::REDACTED;
            } elseif (is_array($value)) {
                $masked[$key] = $this->maskSensitiveData($value);
            } elseif (is_string($value) && $value !== '') {
                $masked[$key] = $this->maskPiiInValue($value);
            } else {
                $masked[$key] = $value;
            }
        }

        return $masked;
    }

    /**
     * Mask PII patterns found in string values
     */
    private function maskPiiInValue(string $value): string
    {
        foreach (self::PII_VALUE_PATTERNS as $pattern) {
            if (preg_match($pattern, $value) === 1) {
                return preg_replace($pattern, self::REDACTED, $value) ?? $value;
            }
        }

        return $value;
    }

    /**
     * Generate a correlation ID
     *
     * Uses cryptographically secure random bytes. If the system has no entropy
     * source available (extremely rare), the exception is propagated as this
     * indicates a critical system configuration issue.
     *
     * @throws RandomException If no suitable random source is available
     */
    private function generateCorrelationId(): string
    {
        return bin2hex(random_bytes(16));
    }
}
