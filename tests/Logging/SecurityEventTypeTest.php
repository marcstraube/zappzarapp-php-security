<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Logging;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Logging\SecurityEventType;

#[CoversClass(SecurityEventType::class)]
final class SecurityEventTypeTest extends TestCase
{
    #[Test]
    public function testAllCasesHaveUniqueValues(): void
    {
        $values       = array_map(fn(SecurityEventType $type) => $type->value, SecurityEventType::cases());
        $uniqueValues = array_unique($values);

        $this->assertCount(count($values), $uniqueValues, 'All event types must have unique values');
    }

    #[Test]
    public function testAllCasesHaveSeverity(): void
    {
        foreach (SecurityEventType::cases() as $type) {
            $severity = $type->severity();
            $this->assertContains($severity, ['warning', 'alert', 'critical']);
        }
    }

    #[Test]
    public function testAllCasesHaveDescription(): void
    {
        foreach (SecurityEventType::cases() as $type) {
            $description = $type->description();
            $this->assertNotEmpty($description);
            $this->assertIsString($description);
        }
    }

    #[DataProvider('warningEventsProvider')]
    #[Test]
    public function testWarningSeverityEvents(SecurityEventType $type): void
    {
        $this->assertSame('warning', $type->severity());
    }

    /**
     * @return iterable<string, array{SecurityEventType}>
     */
    public static function warningEventsProvider(): iterable
    {
        yield 'rate_limit_warning' => [SecurityEventType::RATE_LIMIT_WARNING];
        yield 'password_policy_violation' => [SecurityEventType::PASSWORD_POLICY_VIOLATION];
        yield 'password_weak' => [SecurityEventType::PASSWORD_WEAK];
        yield 'sri_fetch_failure' => [SecurityEventType::SRI_FETCH_FAILURE];
    }

    #[DataProvider('alertEventsProvider')]
    #[Test]
    public function testAlertSeverityEvents(SecurityEventType $type): void
    {
        $this->assertSame('alert', $type->severity());
    }

    /**
     * @return iterable<string, array{SecurityEventType}>
     */
    public static function alertEventsProvider(): iterable
    {
        yield 'csrf_validation_failure' => [SecurityEventType::CSRF_VALIDATION_FAILURE];
        yield 'csrf_token_missing' => [SecurityEventType::CSRF_TOKEN_MISSING];
        yield 'rate_limit_exceeded' => [SecurityEventType::RATE_LIMIT_EXCEEDED];
        yield 'cookie_validation_failure' => [SecurityEventType::COOKIE_VALIDATION_FAILURE];
        yield 'sri_hash_mismatch' => [SecurityEventType::SRI_HASH_MISMATCH];
    }

    #[DataProvider('criticalEventsProvider')]
    #[Test]
    public function testCriticalSeverityEvents(SecurityEventType $type): void
    {
        $this->assertSame('critical', $type->severity());
    }

    /**
     * @return iterable<string, array{SecurityEventType}>
     */
    public static function criticalEventsProvider(): iterable
    {
        yield 'path_traversal_attempt' => [SecurityEventType::PATH_TRAVERSAL_ATTEMPT];
        yield 'xss_attempt_blocked' => [SecurityEventType::XSS_ATTEMPT_BLOCKED];
        yield 'unsafe_uri_blocked' => [SecurityEventType::UNSAFE_URI_BLOCKED];
        yield 'header_injection_attempt' => [SecurityEventType::HEADER_INJECTION_ATTEMPT];
        yield 'password_compromised' => [SecurityEventType::PASSWORD_COMPROMISED];
        yield 'cookie_tampering' => [SecurityEventType::COOKIE_TAMPERING];
        yield 'session_fixation_attempt' => [SecurityEventType::SESSION_FIXATION_ATTEMPT];
    }

    #[Test]
    public function testValueFormat(): void
    {
        foreach (SecurityEventType::cases() as $type) {
            $this->assertMatchesRegularExpression(
                '/^security\.[a-z_]+\.[a-z_]+$/',
                $type->value,
                "Event type value should follow 'security.category.event' format"
            );
        }
    }
}
