<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException or JsonException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Logging;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Logging\SecurityEvent;
use Zappzarapp\Security\Logging\SecurityEventType;

#[CoversClass(SecurityEvent::class)]
final class SecurityEventTest extends TestCase
{
    #[Test]
    public function testConstructorSetsDefaults(): void
    {
        $event = new SecurityEvent(SecurityEventType::CSRF_VALIDATION_FAILURE);

        $this->assertSame(SecurityEventType::CSRF_VALIDATION_FAILURE, $event->type);
        $this->assertSame([], $event->context);
        $this->assertNotEmpty($event->correlationId);
        $this->assertInstanceOf(DateTimeImmutable::class, $event->timestamp);
    }

    #[Test]
    public function testConstructorWithCustomValues(): void
    {
        $timestamp     = new DateTimeImmutable('2024-01-15 10:30:00');
        $context       = ['ip' => '192.168.1.1'];
        $correlationId = 'custom-correlation-id';

        $event = new SecurityEvent(
            SecurityEventType::PATH_TRAVERSAL_ATTEMPT,
            $context,
            $correlationId,
            $timestamp
        );

        $this->assertSame(SecurityEventType::PATH_TRAVERSAL_ATTEMPT, $event->type);
        $this->assertSame($context, $event->context);
        $this->assertSame($correlationId, $event->correlationId);
        $this->assertSame($timestamp, $event->timestamp);
    }

    #[Test]
    public function testWithContextMergesContext(): void
    {
        $event = new SecurityEvent(
            SecurityEventType::RATE_LIMIT_EXCEEDED,
            ['identifier' => 'user:123']
        );

        $newEvent = $event->withContext(['limit' => 100]);

        $this->assertNotSame($event, $newEvent);
        $this->assertSame(['identifier' => 'user:123', 'limit' => 100], $newEvent->context);
        $this->assertSame($event->correlationId, $newEvent->correlationId);
        $this->assertSame($event->timestamp, $newEvent->timestamp);
    }

    #[Test]
    public function testWithCorrelationId(): void
    {
        $event            = new SecurityEvent(SecurityEventType::CSRF_VALIDATION_FAILURE);
        $newCorrelationId = 'new-correlation-id';

        $newEvent = $event->withCorrelationId($newCorrelationId);

        $this->assertNotSame($event, $newEvent);
        $this->assertSame($newCorrelationId, $newEvent->correlationId);
        $this->assertSame($event->type, $newEvent->type);
        $this->assertSame($event->context, $newEvent->context);
        $this->assertSame($event->timestamp, $newEvent->timestamp);
    }

    #[Test]
    public function testSeverityDelegatestoType(): void
    {
        $event = new SecurityEvent(SecurityEventType::PASSWORD_COMPROMISED);

        $this->assertSame('critical', $event->severity());
    }

    #[Test]
    public function testMessageDelegatesToType(): void
    {
        $event = new SecurityEvent(SecurityEventType::RATE_LIMIT_EXCEEDED);

        $this->assertSame('Rate limit has been exceeded', $event->message());
    }

    #[Test]
    public function testToArrayReturnsCorrectStructure(): void
    {
        $timestamp = new DateTimeImmutable('2024-01-15 10:30:00');
        $event     = new SecurityEvent(
            SecurityEventType::PATH_TRAVERSAL_ATTEMPT,
            ['path' => '/etc/passwd'],
            'test-correlation-id',
            $timestamp
        );

        $array = $event->toArray();

        $this->assertSame('security.input.path_traversal', $array['event_type']);
        $this->assertSame('critical', $array['severity']);
        $this->assertSame('Path traversal attack attempt detected', $array['message']);
        $this->assertSame('test-correlation-id', $array['correlation_id']);
        $this->assertSame($timestamp->format('c'), $array['timestamp']);
        $this->assertSame(['path' => '/etc/passwd'], $array['context']);
    }

    #[Test]
    public function testToJsonReturnsValidJson(): void
    {
        $event = new SecurityEvent(
            SecurityEventType::CSRF_VALIDATION_FAILURE,
            ['reason' => 'mismatch'],
            'json-test-id'
        );

        $json    = $event->toJson();
        $decoded = json_decode($json, true);

        $this->assertIsArray($decoded);
        $this->assertSame('security.csrf.validation_failure', $decoded['event_type']);
        $this->assertSame('json-test-id', $decoded['correlation_id']);
    }

    #[Test]
    public function testToJsonUsesUnescapedSlashes(): void
    {
        // This test verifies JSON_UNESCAPED_SLASHES is used (kills BitwiseOr mutant)
        $event = new SecurityEvent(
            SecurityEventType::PATH_TRAVERSAL_ATTEMPT,
            ['path' => '/etc/passwd'],
            'slash-test-id'
        );

        $json = $event->toJson();

        // With JSON_UNESCAPED_SLASHES, slashes should NOT be escaped as \/
        $this->assertStringContainsString('/etc/passwd', $json);
        $this->assertStringNotContainsString('\\/etc\\/passwd', $json);
    }

    #[Test]
    public function testToJsonWithUrlPath(): void
    {
        // Another test to ensure slashes are unescaped
        $event = new SecurityEvent(
            SecurityEventType::RATE_LIMIT_EXCEEDED,
            ['endpoint' => 'https://example.com/api/v1/users'],
            'url-test-id'
        );

        $json = $event->toJson();

        // Forward slashes should be literal, not escaped
        $this->assertStringContainsString('https://example.com/api/v1/users', $json);
    }

    #[Test]
    public function testToStringReturnsFormattedMessage(): void
    {
        $timestamp = new DateTimeImmutable('2024-01-15 10:30:00');
        $event     = new SecurityEvent(
            SecurityEventType::PASSWORD_COMPROMISED,
            [],
            'string-test-id',
            $timestamp
        );

        $string = (string) $event;

        $this->assertStringContainsString('CRITICAL', $string);
        $this->assertStringContainsString('Password found in breach database', $string);
        $this->assertStringContainsString('string-test-id', $string);
    }

    #[Test]
    public function testCsrfFailureFactory(): void
    {
        $event = SecurityEvent::csrfFailure(['ip' => '10.0.0.1']);

        $this->assertSame(SecurityEventType::CSRF_VALIDATION_FAILURE, $event->type);
        $this->assertSame(['ip' => '10.0.0.1'], $event->context);
    }

    #[Test]
    public function testRateLimitExceededFactory(): void
    {
        $event = SecurityEvent::rateLimitExceeded('user:456', 100, 60, ['endpoint' => '/api/users']);

        $this->assertSame(SecurityEventType::RATE_LIMIT_EXCEEDED, $event->type);
        $this->assertSame('user:456', $event->context['identifier']);
        $this->assertSame(100, $event->context['limit']);
        $this->assertSame(60, $event->context['retry_after']);
        $this->assertSame('/api/users', $event->context['endpoint']);
    }

    #[Test]
    public function testPathTraversalFactory(): void
    {
        $event = SecurityEvent::pathTraversal('../../../etc/passwd', 'traversal_sequence', ['ip' => '10.0.0.1']);

        $this->assertSame(SecurityEventType::PATH_TRAVERSAL_ATTEMPT, $event->type);
        $this->assertSame('../../../etc/passwd', $event->context['path']);
        $this->assertSame('traversal_sequence', $event->context['reason']);
        $this->assertSame('10.0.0.1', $event->context['ip']);
    }

    #[Test]
    public function testPasswordCompromisedFactory(): void
    {
        $event = SecurityEvent::passwordCompromised(1234, ['user_id' => 42]);

        $this->assertSame(SecurityEventType::PASSWORD_COMPROMISED, $event->type);
        $this->assertSame(1234, $event->context['occurrences']);
        $this->assertSame(42, $event->context['user_id']);
    }

    #[Test]
    public function testCorrelationIdIsUniquePerInstance(): void
    {
        $event1 = new SecurityEvent(SecurityEventType::CSRF_VALIDATION_FAILURE);
        $event2 = new SecurityEvent(SecurityEventType::CSRF_VALIDATION_FAILURE);

        $this->assertNotSame($event1->correlationId, $event2->correlationId);
    }

    #[Test]
    public function testCorrelationIdFormat(): void
    {
        $event = new SecurityEvent(SecurityEventType::CSRF_VALIDATION_FAILURE);

        // Should be 32 hex characters (16 bytes)
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $event->correlationId);
    }

    #[Test]
    public function testCsrfTokenMissingFactory(): void
    {
        $event = SecurityEvent::csrfTokenMissing(['ip' => '10.0.0.1']);

        $this->assertSame(SecurityEventType::CSRF_TOKEN_MISSING, $event->type);
        $this->assertSame(['ip' => '10.0.0.1'], $event->context);
    }

    #[Test]
    public function testSessionFixationAttemptFactory(): void
    {
        $event = SecurityEvent::sessionFixationAttempt('external_session_id', ['ip' => '10.0.0.1']);

        $this->assertSame(SecurityEventType::SESSION_FIXATION_ATTEMPT, $event->type);
        $this->assertSame('external_session_id', $event->context['reason']);
        $this->assertSame('10.0.0.1', $event->context['ip']);
    }

    #[Test]
    public function testRateLimitWarningFactory(): void
    {
        $event = SecurityEvent::rateLimitWarning('user:123', 80, 100, ['endpoint' => '/api']);

        $this->assertSame(SecurityEventType::RATE_LIMIT_WARNING, $event->type);
        $this->assertSame('user:123', $event->context['identifier']);
        $this->assertSame(80, $event->context['current']);
        $this->assertSame(100, $event->context['limit']);
        $this->assertSame('/api', $event->context['endpoint']);
    }

    #[Test]
    public function testXssBlockedFactory(): void
    {
        $maliciousInput = '<script>alert("xss")</script>';
        $event          = SecurityEvent::xssBlocked($maliciousInput, 'script_tag', ['field' => 'comment']);

        $this->assertSame(SecurityEventType::XSS_ATTEMPT_BLOCKED, $event->type);
        $this->assertSame($maliciousInput, $event->context['input']);
        $this->assertSame('script_tag', $event->context['reason']);
        $this->assertSame('comment', $event->context['field']);
    }

    #[Test]
    public function testXssBlockedTruncatesLongInput(): void
    {
        $longInput = str_repeat('x', 300);
        $event     = SecurityEvent::xssBlocked($longInput, 'test');

        $this->assertSame(200, mb_strlen($event->context['input']));
    }

    #[Test]
    public function testUnsafeUriBlockedFactory(): void
    {
        $event = SecurityEvent::unsafeUriBlocked('javascript:alert(1)', 'javascript_scheme', ['field' => 'url']);

        $this->assertSame(SecurityEventType::UNSAFE_URI_BLOCKED, $event->type);
        $this->assertSame('javascript:alert(1)', $event->context['uri']);
        $this->assertSame('javascript_scheme', $event->context['reason']);
        $this->assertSame('url', $event->context['field']);
    }

    #[Test]
    public function testHeaderInjectionAttemptFactory(): void
    {
        $event = SecurityEvent::headerInjectionAttempt('Location', 'crlf_detected', ['ip' => '10.0.0.1']);

        $this->assertSame(SecurityEventType::HEADER_INJECTION_ATTEMPT, $event->type);
        $this->assertSame('Location', $event->context['header']);
        $this->assertSame('crlf_detected', $event->context['reason']);
        $this->assertSame('10.0.0.1', $event->context['ip']);
    }

    #[Test]
    public function testPasswordPolicyViolationFactory(): void
    {
        $violations = ['too_short', 'no_uppercase'];
        $event      = SecurityEvent::passwordPolicyViolation($violations, ['user_id' => 42]);

        $this->assertSame(SecurityEventType::PASSWORD_POLICY_VIOLATION, $event->type);
        $this->assertSame($violations, $event->context['violations']);
        $this->assertSame(42, $event->context['user_id']);
    }

    #[Test]
    public function testPasswordWeakFactory(): void
    {
        $event = SecurityEvent::passwordWeak('weak', 25.5, ['user_id' => 42]);

        $this->assertSame(SecurityEventType::PASSWORD_WEAK, $event->type);
        $this->assertSame('weak', $event->context['strength_level']);
        $this->assertSame(25.5, $event->context['entropy']);
        $this->assertSame(42, $event->context['user_id']);
    }

    #[Test]
    public function testCookieTamperingFactory(): void
    {
        $event = SecurityEvent::cookieTampering('session_id', 'signature_mismatch', ['ip' => '10.0.0.1']);

        $this->assertSame(SecurityEventType::COOKIE_TAMPERING, $event->type);
        $this->assertSame('session_id', $event->context['cookie_name']);
        $this->assertSame('signature_mismatch', $event->context['reason']);
        $this->assertSame('10.0.0.1', $event->context['ip']);
    }

    #[Test]
    public function testCookieValidationFailureFactory(): void
    {
        $event = SecurityEvent::cookieValidationFailure('auth', 'expired', ['ip' => '10.0.0.1']);

        $this->assertSame(SecurityEventType::COOKIE_VALIDATION_FAILURE, $event->type);
        $this->assertSame('auth', $event->context['cookie_name']);
        $this->assertSame('expired', $event->context['reason']);
        $this->assertSame('10.0.0.1', $event->context['ip']);
    }

    #[Test]
    public function testSriHashMismatchFactory(): void
    {
        $event = SecurityEvent::sriHashMismatch(
            'https://cdn.example.com/script.js',
            'sha384-expected',
            'sha384-actual',
            ['page' => '/checkout']
        );

        $this->assertSame(SecurityEventType::SRI_HASH_MISMATCH, $event->type);
        $this->assertSame('https://cdn.example.com/script.js', $event->context['url']);
        $this->assertSame('sha384-expected', $event->context['expected']);
        $this->assertSame('sha384-actual', $event->context['actual']);
        $this->assertSame('/checkout', $event->context['page']);
    }

    #[Test]
    public function testSriFetchFailureFactory(): void
    {
        $event = SecurityEvent::sriFetchFailure(
            'https://cdn.example.com/script.js',
            'connection_timeout',
            ['attempt' => 3]
        );

        $this->assertSame(SecurityEventType::SRI_FETCH_FAILURE, $event->type);
        $this->assertSame('https://cdn.example.com/script.js', $event->context['url']);
        $this->assertSame('connection_timeout', $event->context['reason']);
        $this->assertSame(3, $event->context['attempt']);
    }
}
