<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Logging;

use DateTimeImmutable;
use JsonException;
use Override;
use Random\RandomException;
use Stringable;

/**
 * Immutable security event for structured audit logging
 *
 * Encapsulates all information about a security event including
 * type, context, correlation ID, and timestamp.
 */
final readonly class SecurityEvent implements Stringable
{
    private const string CORRELATION_ID_BYTES = '16';

    public string $correlationId;

    /**
     * @param SecurityEventType $type The event type
     * @param array<string, mixed> $context Additional context data
     * @param string|null $correlationId Optional correlation ID (generated if null)
     * @param DateTimeImmutable $timestamp Timestamp (defaults to now)
     *
     * @throws RandomException If correlation ID generation fails
     */
    public function __construct(
        public SecurityEventType $type,
        public array $context = [],
        ?string $correlationId = null,
        public DateTimeImmutable $timestamp = new DateTimeImmutable(),
    ) {
        $this->correlationId = $correlationId ?? $this->generateCorrelationId();
    }

    /**
     * Create event with additional context
     *
     * @param array<string, mixed> $context Additional context to merge
     *
     * @throws RandomException If correlation ID generation fails
     */
    public function withContext(array $context): self
    {
        return new self(
            $this->type,
            [...$this->context, ...$context],
            $this->correlationId,
            $this->timestamp
        );
    }

    /**
     * Create event with specific correlation ID
     *
     * @throws RandomException If correlation ID generation fails
     */
    public function withCorrelationId(string $correlationId): self
    {
        return new self(
            $this->type,
            $this->context,
            $correlationId,
            $this->timestamp
        );
    }

    /**
     * Get the event severity level
     *
     * @return 'warning'|'alert'|'critical'
     */
    public function severity(): string
    {
        return $this->type->severity();
    }

    /**
     * Get the event message
     */
    public function message(): string
    {
        return $this->type->description();
    }

    /**
     * Convert to array for logging
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'event_type'     => $this->type->value,
            'severity'       => $this->severity(),
            'message'        => $this->message(),
            'correlation_id' => $this->correlationId,
            'timestamp'      => $this->timestamp->format('c'),
            'context'        => $this->context,
        ];
    }

    /**
     * Convert to JSON string
     *
     * @throws JsonException If JSON encoding fails
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    #[Override]
    public function __toString(): string
    {
        return sprintf(
            '[%s] %s: %s (correlation_id=%s)',
            $this->timestamp->format('c'),
            strtoupper($this->severity()),
            $this->message(),
            $this->correlationId
        );
    }

    /**
     * Generate a unique correlation ID
     *
     * @throws RandomException If no suitable random source is available
     */
    private function generateCorrelationId(): string
    {
        $bytes = random_bytes((int) self::CORRELATION_ID_BYTES);

        return bin2hex($bytes);
    }

    /**
     * Create a CSRF validation failure event
     *
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function csrfFailure(array $context = []): self
    {
        return new self(SecurityEventType::CSRF_VALIDATION_FAILURE, $context);
    }

    /**
     * Create a rate limit exceeded event
     *
     * @param string $identifier The rate-limited identifier
     * @param int $limit The configured limit
     * @param int $retryAfter Seconds until retry is allowed
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function rateLimitExceeded(
        string $identifier,
        int $limit,
        int $retryAfter,
        array $context = [],
    ): self {
        return new self(SecurityEventType::RATE_LIMIT_EXCEEDED, [
            'identifier'  => $identifier,
            'limit'       => $limit,
            'retry_after' => $retryAfter,
            ...$context,
        ]);
    }

    /**
     * Create a path traversal attempt event
     *
     * @param string $path The attempted path
     * @param string $reason The detection reason
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function pathTraversal(string $path, string $reason, array $context = []): self
    {
        return new self(SecurityEventType::PATH_TRAVERSAL_ATTEMPT, [
            'path'   => $path,
            'reason' => $reason,
            ...$context,
        ]);
    }

    /**
     * Create a compromised password event
     *
     * @param int $occurrences Number of times found in breaches
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function passwordCompromised(int $occurrences, array $context = []): self
    {
        return new self(SecurityEventType::PASSWORD_COMPROMISED, [
            'occurrences' => $occurrences,
            ...$context,
        ]);
    }

    /**
     * Create a CSRF token missing event
     *
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function csrfTokenMissing(array $context = []): self
    {
        return new self(SecurityEventType::CSRF_TOKEN_MISSING, $context);
    }

    /**
     * Create a session fixation attempt event
     *
     * @param string $reason Detection reason
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function sessionFixationAttempt(string $reason, array $context = []): self
    {
        return new self(SecurityEventType::SESSION_FIXATION_ATTEMPT, [
            'reason' => $reason,
            ...$context,
        ]);
    }

    /**
     * Create a rate limit warning event (threshold approaching)
     *
     * @param string $identifier The rate-limited identifier
     * @param int $current Current usage count
     * @param int $limit The configured limit
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function rateLimitWarning(
        string $identifier,
        int $current,
        int $limit,
        array $context = [],
    ): self {
        return new self(SecurityEventType::RATE_LIMIT_WARNING, [
            'identifier' => $identifier,
            'current'    => $current,
            'limit'      => $limit,
            ...$context,
        ]);
    }

    /**
     * Create an XSS attempt blocked event
     *
     * @param string $input The blocked input (truncated for safety)
     * @param string $reason Detection reason
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function xssBlocked(string $input, string $reason, array $context = []): self
    {
        return new self(SecurityEventType::XSS_ATTEMPT_BLOCKED, [
            'input'  => mb_substr($input, 0, 200),
            'reason' => $reason,
            ...$context,
        ]);
    }

    /**
     * Create an unsafe URI blocked event
     *
     * @param string $uri The blocked URI
     * @param string $reason Detection reason
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function unsafeUriBlocked(string $uri, string $reason, array $context = []): self
    {
        return new self(SecurityEventType::UNSAFE_URI_BLOCKED, [
            'uri'    => $uri,
            'reason' => $reason,
            ...$context,
        ]);
    }

    /**
     * Create a header injection attempt event
     *
     * @param string $header The header name
     * @param string $reason Detection reason
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function headerInjectionAttempt(string $header, string $reason, array $context = []): self
    {
        return new self(SecurityEventType::HEADER_INJECTION_ATTEMPT, [
            'header' => $header,
            'reason' => $reason,
            ...$context,
        ]);
    }

    /**
     * Create a password policy violation event
     *
     * @param list<string> $violations List of violated rules
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function passwordPolicyViolation(array $violations, array $context = []): self
    {
        return new self(SecurityEventType::PASSWORD_POLICY_VIOLATION, [
            'violations' => $violations,
            ...$context,
        ]);
    }

    /**
     * Create a weak password event
     *
     * @param string $strengthLevel The detected strength level
     * @param float $entropy The calculated entropy
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function passwordWeak(string $strengthLevel, float $entropy, array $context = []): self
    {
        return new self(SecurityEventType::PASSWORD_WEAK, [
            'strength_level' => $strengthLevel,
            'entropy'        => $entropy,
            ...$context,
        ]);
    }

    /**
     * Create a cookie tampering event
     *
     * @param string $cookieName The affected cookie name
     * @param string $reason Detection reason
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function cookieTampering(string $cookieName, string $reason, array $context = []): self
    {
        return new self(SecurityEventType::COOKIE_TAMPERING, [
            'cookie_name' => $cookieName,
            'reason'      => $reason,
            ...$context,
        ]);
    }

    /**
     * Create a cookie validation failure event
     *
     * @param string $cookieName The affected cookie name
     * @param string $reason Validation failure reason
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function cookieValidationFailure(string $cookieName, string $reason, array $context = []): self
    {
        return new self(SecurityEventType::COOKIE_VALIDATION_FAILURE, [
            'cookie_name' => $cookieName,
            'reason'      => $reason,
            ...$context,
        ]);
    }

    /**
     * Create an SRI hash mismatch event
     *
     * @param string $url The resource URL
     * @param string $expected Expected hash
     * @param string $actual Actual hash
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function sriHashMismatch(
        string $url,
        string $expected,
        string $actual,
        array $context = [],
    ): self {
        return new self(SecurityEventType::SRI_HASH_MISMATCH, [
            'url'      => $url,
            'expected' => $expected,
            'actual'   => $actual,
            ...$context,
        ]);
    }

    /**
     * Create an SRI fetch failure event
     *
     * @param string $url The resource URL
     * @param string $reason Failure reason
     * @param array<string, mixed> $context Additional context
     *
     * @throws RandomException If correlation ID generation fails
     */
    public static function sriFetchFailure(string $url, string $reason, array $context = []): self
    {
        return new self(SecurityEventType::SRI_FETCH_FAILURE, [
            'url'    => $url,
            'reason' => $reason,
            ...$context,
        ]);
    }
}
