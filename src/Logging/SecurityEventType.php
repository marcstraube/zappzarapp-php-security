<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Logging;

/**
 * Security event types for structured audit logging
 *
 * Categorizes security events for monitoring, alerting, and analysis.
 */
enum SecurityEventType: string
{
    // Authentication & Session
    case CSRF_VALIDATION_FAILURE  = 'security.csrf.validation_failure';
    case CSRF_TOKEN_MISSING       = 'security.csrf.token_missing';
    case SESSION_FIXATION_ATTEMPT = 'security.session.fixation_attempt';

    // Rate Limiting
    case RATE_LIMIT_EXCEEDED = 'security.rate_limit.exceeded';
    case RATE_LIMIT_WARNING  = 'security.rate_limit.warning';

    // Input Validation
    case PATH_TRAVERSAL_ATTEMPT   = 'security.input.path_traversal';
    case XSS_ATTEMPT_BLOCKED      = 'security.input.xss_blocked';
    case UNSAFE_URI_BLOCKED       = 'security.input.unsafe_uri';
    case HEADER_INJECTION_ATTEMPT = 'security.input.header_injection';

    // Password Security
    case PASSWORD_COMPROMISED      = 'security.password.compromised';
    case PASSWORD_POLICY_VIOLATION = 'security.password.policy_violation';
    case PASSWORD_WEAK             = 'security.password.weak';

    // Cookie Security
    case COOKIE_TAMPERING          = 'security.cookie.tampering';
    case COOKIE_VALIDATION_FAILURE = 'security.cookie.validation_failure';

    // SRI
    case SRI_HASH_MISMATCH = 'security.sri.hash_mismatch';
    case SRI_FETCH_FAILURE = 'security.sri.fetch_failure';

    /**
     * Get the severity level for this event type
     *
     * @return 'warning'|'alert'|'critical'
     */
    public function severity(): string
    {
        return match ($this) {
            self::RATE_LIMIT_WARNING,
            self::PASSWORD_POLICY_VIOLATION,
            self::PASSWORD_WEAK,
            self::SRI_FETCH_FAILURE => 'warning',

            self::CSRF_VALIDATION_FAILURE,
            self::CSRF_TOKEN_MISSING,
            self::RATE_LIMIT_EXCEEDED,
            self::COOKIE_VALIDATION_FAILURE,
            self::SRI_HASH_MISMATCH => 'alert',

            self::PATH_TRAVERSAL_ATTEMPT,
            self::XSS_ATTEMPT_BLOCKED,
            self::UNSAFE_URI_BLOCKED,
            self::HEADER_INJECTION_ATTEMPT,
            self::PASSWORD_COMPROMISED,
            self::COOKIE_TAMPERING,
            self::SESSION_FIXATION_ATTEMPT => 'critical',
        };
    }

    /**
     * Get a human-readable description
     */
    public function description(): string
    {
        return match ($this) {
            self::CSRF_VALIDATION_FAILURE   => 'CSRF token validation failed',
            self::CSRF_TOKEN_MISSING        => 'CSRF token was not provided',
            self::SESSION_FIXATION_ATTEMPT  => 'Possible session fixation attack detected',
            self::RATE_LIMIT_EXCEEDED       => 'Rate limit has been exceeded',
            self::RATE_LIMIT_WARNING        => 'Rate limit threshold approaching',
            self::PATH_TRAVERSAL_ATTEMPT    => 'Path traversal attack attempt detected',
            self::XSS_ATTEMPT_BLOCKED       => 'XSS attack attempt was blocked',
            self::UNSAFE_URI_BLOCKED        => 'Unsafe URI scheme was blocked',
            self::HEADER_INJECTION_ATTEMPT  => 'HTTP header injection attempt detected',
            self::PASSWORD_COMPROMISED      => 'Password found in breach database',
            self::PASSWORD_POLICY_VIOLATION => 'Password does not meet policy requirements',
            self::PASSWORD_WEAK             => 'Password has insufficient entropy',
            self::COOKIE_TAMPERING          => 'Cookie tampering detected',
            self::COOKIE_VALIDATION_FAILURE => 'Cookie validation failed',
            self::SRI_HASH_MISMATCH         => 'Subresource integrity hash mismatch',
            self::SRI_FETCH_FAILURE         => 'Failed to fetch resource for SRI verification',
        };
    }
}
