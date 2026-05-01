<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */
/** @noinspection PhpMultipleClassDeclarationsInspection Stringable exists in PHP core and polyfills */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Logging;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Stringable;
use Zappzarapp\Security\Logging\SecurityAuditLogger;
use Zappzarapp\Security\Logging\SecurityEvent;
use Zappzarapp\Security\Logging\SecurityEventType;

#[CoversClass(SecurityAuditLogger::class)]
final class SecurityAuditLoggerTest extends TestCase
{
    #[Test]
    public function testWarningDelegatesToPsrLogger(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                'Test warning',
                $this->callback(fn(array $context) => $context['test_key'] === 'test_value'
                    && isset($context['correlation_id'])
                    && $context['security_component'] === 'zappzarapp/security')
            );

        $logger->warning('Test warning', ['test_key' => 'test_value']);
    }

    #[Test]
    public function testAlertDelegatesToPsrLogger(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $psrLogger->expects($this->once())
            ->method('alert')
            ->with(
                'Test alert',
                $this->callback(fn(array $context) => $context['alert_key'] === 'alert_value'
                    && isset($context['correlation_id']))
            );

        $logger->alert('Test alert', ['alert_key' => 'alert_value']);
    }

    #[Test]
    public function testCriticalDelegatesToPsrLogger(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $psrLogger->expects($this->once())
            ->method('critical')
            ->with(
                'Test critical',
                $this->callback(fn(array $context) => $context['critical_key'] === 'critical_value'
                    && isset($context['correlation_id']))
            );

        $logger->critical('Test critical', ['critical_key' => 'critical_value']);
    }

    #[Test]
    public function testCorrelationIdIsConsistentAcrossCalls(): void
    {
        $calls         = [];
        $psrLoggerStub = $this->createStub(LoggerInterface::class);

        $psrLoggerStub->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$calls): void {
                $calls[] = ['message' => $message, 'correlation_id' => $context['correlation_id']];
            });

        $logger = new SecurityAuditLogger($psrLoggerStub);

        $logger->warning('First');
        $logger->warning('Second');

        $this->assertCount(2, $calls);
        $this->assertSame('First', $calls[0]['message']);
        $this->assertSame('Second', $calls[1]['message']);
        $this->assertSame($calls[0]['correlation_id'], $calls[1]['correlation_id']);
    }

    #[Test]
    public function testCustomCorrelationId(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $customId  = 'my-custom-correlation-id';
        $logger    = new SecurityAuditLogger($psrLogger, $customId);

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['correlation_id'] === $customId)
            );

        $logger->warning('Test');
    }

    #[Test]
    public function testWithCorrelationIdReturnsNewInstance(): void
    {
        $psrLoggerStub = $this->createStub(LoggerInterface::class);
        $logger        = new SecurityAuditLogger($psrLoggerStub);
        $newLogger     = $logger->withCorrelationId('new-id');

        $this->assertNotSame($logger, $newLogger);
        $this->assertSame('new-id', $newLogger->correlationId());
    }

    #[Test]
    public function testCorrelationIdAccessor(): void
    {
        $psrLoggerStub = $this->createStub(LoggerInterface::class);
        $logger        = new SecurityAuditLogger($psrLoggerStub, 'test-id');

        $this->assertSame('test-id', $logger->correlationId());
    }

    #[Test]
    public function testSecurityEventLogsWithWarningSeverity(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);
        $event     = new SecurityEvent(
            SecurityEventType::RATE_LIMIT_WARNING,
            ['identifier' => 'user:123']
        );

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                'Rate limit threshold approaching',
                $this->callback(fn(array $context) => $context['event_type'] === 'security.rate_limit.warning'
                    && $context['identifier'] === 'user:123')
            );

        $logger->securityEvent($event);
    }

    #[Test]
    public function testSecurityEventLogsWithAlertSeverity(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);
        $event     = new SecurityEvent(
            SecurityEventType::RATE_LIMIT_EXCEEDED,
            ['identifier' => 'user:456']
        );

        $psrLogger->expects($this->once())
            ->method('alert')
            ->with(
                'Rate limit has been exceeded',
                $this->callback(fn(array $context) => $context['event_type'] === 'security.rate_limit.exceeded')
            );

        $logger->securityEvent($event);
    }

    #[Test]
    public function testSecurityEventLogsWithCriticalSeverity(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);
        $event     = new SecurityEvent(
            SecurityEventType::PATH_TRAVERSAL_ATTEMPT,
            ['path' => '/etc/passwd']
        );

        $psrLogger->expects($this->once())
            ->method('critical')
            ->with(
                'Path traversal attack attempt detected',
                $this->callback(fn(array $context) => $context['event_type'] === 'security.input.path_traversal'
                    && $context['path'] === '/etc/passwd')
            );

        $logger->securityEvent($event);
    }

    #[Test]
    public function testSecurityEventIncludesEventTimestamp(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);
        $event     = new SecurityEvent(SecurityEventType::CSRF_VALIDATION_FAILURE);

        $psrLogger->expects($this->once())
            ->method('alert')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => isset($context['event_timestamp'])
                    && isset($context['correlation_id']))
            );

        $logger->securityEvent($event);
    }

    #[Test]
    public function testSecurityEventUsesEventsCorrelationIdIfPresent(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger, 'logger-id');
        $event     = new SecurityEvent(
            SecurityEventType::CSRF_VALIDATION_FAILURE,
            [],
            'event-specific-id'
        );

        $psrLogger->expects($this->once())
            ->method('alert')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['correlation_id'] === 'event-specific-id')
            );

        $logger->securityEvent($event);
    }

    #[Test]
    public function testContextEnrichmentIncludesSecurityComponent(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['security_component'] === 'zappzarapp/security')
            );

        $logger->warning('Test');
    }

    #[Test]
    public function testProvidedCorrelationIdOverridesDefault(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['correlation_id'] === 'provided-id')
            );

        $logger->warning('Test', ['correlation_id' => 'provided-id']);
    }

    #[Test]
    public function testContextCorrelationIdTakesPrecedenceOverLoggerDefault(): void
    {
        // This tests the coalesce order: $context['correlation_id'] ?? $this->correlationId
        // The mutant swaps this to: $this->correlationId ?? $context['correlation_id']
        // IMPORTANT: Both IDs are non-null, so only order matters
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger, 'logger-default-id');

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $this->assertSame('Test', $message);
                $capturedContext = $context;
            });

        // Context-provided correlation_id should override the logger's default
        $logger->warning('Test', ['correlation_id' => 'context-provided-id']);

        // The context['correlation_id'] MUST take precedence over logger's default
        // If mutant swaps order: $this->correlationId ?? $context['correlation_id']
        // then it would return 'logger-default-id' since $this->correlationId is not null
        $this->assertNotNull($capturedContext);
        $this->assertArrayHasKey('correlation_id', $capturedContext);
        $this->assertSame('context-provided-id', $capturedContext['correlation_id']);
    }

    #[Test]
    public function testDefaultCorrelationIdUsedWhenNotInContext(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger, 'logger-default-id');

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['correlation_id'] === 'logger-default-id')
            );

        // No correlation_id in context, should use logger's default
        $logger->warning('Test', ['other_key' => 'value']);
    }

    #[Test]
    public function testGeneratedCorrelationIdHasCorrectLength(): void
    {
        // This test kills the DecrementInteger/IncrementInteger mutants
        // random_bytes(16) produces 32 hex chars, mutants would produce 30 or 34
        $psrLoggerStub = $this->createStub(LoggerInterface::class);
        $logger        = new SecurityAuditLogger($psrLoggerStub);

        $correlationId = $logger->correlationId();

        // Must be exactly 32 hex characters (16 bytes = 32 hex chars)
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $correlationId);
        $this->assertSame(32, strlen($correlationId));
    }

    #[Test]
    public function testMultipleLoggersHaveUniqueCorrelationIds(): void
    {
        $psrLoggerStub = $this->createStub(LoggerInterface::class);
        $logger1       = new SecurityAuditLogger($psrLoggerStub);
        $logger2       = new SecurityAuditLogger($psrLoggerStub);

        $this->assertNotSame($logger1->correlationId(), $logger2->correlationId());
    }

    #[Test]
    public function testSensitiveDataIsMaskedInContext(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['password'] === '***REDACTED***'
                    && $context['token'] === '***REDACTED***'
                    && $context['api_key'] === '***REDACTED***'
                    && $context['username'] === 'john_doe')
            );

        $logger->warning('Test', [
            'username' => 'john_doe',
            'password' => 'secret123',
            'token'    => 'abc123xyz',
            'api_key'  => 'key-12345',
        ]);
    }

    #[Test]
    public function testSensitiveDataMaskingIsRecursive(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['user']['password'] === '***REDACTED***'
                    && $context['user']['name'] === 'Alice')
            );

        $logger->warning('Test', [
            'user' => [
                'name'     => 'Alice',
                'password' => 'secret',
            ],
        ]);
    }

    #[Test]
    public function testSensitiveKeyVariationsAreMasked(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['API_KEY'] === '***REDACTED***'
                    && $context['apikey'] === '***REDACTED***'
                    && $context['api-key'] === '***REDACTED***'
                    && $context['access_token'] === '***REDACTED***'
                    && $context['authorization'] === '***REDACTED***')
            );

        $logger->warning('Test', [
            'API_KEY'       => 'key1',
            'apikey'        => 'key2',
            'api-key'       => 'key3',
            'access_token'  => 'token1',
            'authorization' => 'Bearer xyz',
        ]);
    }

    #[Test]
    public function testEmptySensitiveValuesAreNotMasked(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['password'] === ''
                    && $context['token'] === null)
            );

        $logger->warning('Test', [
            'password' => '',
            'token'    => null,
        ]);
    }

    #[Test]
    public function testPartialSensitiveKeyMatchIsMasked(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $psrLogger->expects($this->once())
            ->method('warning')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['user_password'] === '***REDACTED***'
                    && $context['github_token'] === '***REDACTED***'
                    && $context['my_api_key_value'] === '***REDACTED***')
            );

        $logger->warning('Test', [
            'user_password'    => 'secret1',
            'github_token'     => 'ghp_xxx',
            'my_api_key_value' => 'key123',
        ]);
    }

    // =========================================================================
    // Context Size Limits (DoS Prevention)
    // =========================================================================

    #[Test]
    public function testContextKeysAreLimitedTo50(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        // Create context with 60 keys
        $context = [];
        for ($i = 0; $i < 60; $i++) {
            /** @noinspection PhpUnnecessaryCurlyVarSyntaxInspection Curly braces improve readability */
            $context["key_{$i}"] = "value_{$i}";
        }

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', $context);

        // Should have at most 50 user keys + 2 system keys (correlation_id, security_component) + truncation marker
        $this->assertNotNull($capturedContext);
        // First 50 user keys should be present
        $this->assertArrayHasKey('key_0', $capturedContext);
        $this->assertArrayHasKey('key_49', $capturedContext);
        // Truncation marker should be present
        $this->assertArrayHasKey('***TRUNCATED***', $capturedContext);
    }

    #[Test]
    public function testContextDepthIsLimitedTo5(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        // Create deeply nested array (depth 7)
        $deeply = ['level' => 7];
        $deeply = ['level' => 6, 'child' => $deeply];
        $deeply = ['level' => 5, 'child' => $deeply];
        $deeply = ['level' => 4, 'child' => $deeply];
        $deeply = ['level' => 3, 'child' => $deeply];
        $deeply = ['level' => 2, 'child' => $deeply];
        $deeply = ['level' => 1, 'child' => $deeply];

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', ['nested' => $deeply]);

        // Navigate to depth 5 - should find truncation marker instead of more nesting
        $this->assertNotNull($capturedContext);
        $level1 = $capturedContext['nested'];
        $level2 = $level1['child'];
        $level3 = $level2['child'];
        $level4 = $level3['child'];
        $level5 = $level4['child'];

        // At depth 5, further nesting should be truncated
        $this->assertArrayHasKey('***TRUNCATED***', $level5);
    }

    #[Test]
    public function testContextStringLengthIsLimitedTo1000(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $longString = str_repeat('x', 2000);

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', ['long' => $longString]);

        $this->assertNotNull($capturedContext);
        // String should be truncated to 1000 chars + "...***TRUNCATED***"
        $this->assertStringContainsString('***TRUNCATED***', $capturedContext['long']);
        $this->assertLessThan(2000, strlen($capturedContext['long']));
    }

    #[Test]
    public function testContextWithinLimitsIsNotTruncated(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        $context = [
            'key1' => 'short value',
            'key2' => ['nested' => 'value'],
        ];

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', $context);

        $this->assertNotNull($capturedContext);
        $this->assertSame('short value', $capturedContext['key1']);
        $this->assertSame('value', $capturedContext['key2']['nested']);
        $this->assertArrayNotHasKey('***TRUNCATED***', $capturedContext);
    }

    // =========================================================================
    // Log Injection Prevention
    // =========================================================================

    #[Test]
    public function testNewlinesAreEscapedInContext(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', [
            'user_input' => "malicious\ninjected\rlog\r\nentry",
        ]);

        $this->assertNotNull($capturedContext);
        $this->assertSame('malicious\\ninjected\\rlog\\r\\nentry', $capturedContext['user_input']);
        $this->assertStringNotContainsString("\n", $capturedContext['user_input']);
        $this->assertStringNotContainsString("\r", $capturedContext['user_input']);
    }

    #[Test]
    public function testNewlineEscapingIsRecursive(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', [
            'nested' => [
                'value' => "line1\nline2",
            ],
        ]);

        $this->assertNotNull($capturedContext);
        $this->assertSame('line1\\nline2', $capturedContext['nested']['value']);
    }

    #[Test]
    public function testNonStringValuesArePreserved(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', [
            'count'   => 42,
            'enabled' => true,
            'ratio'   => 3.14,
            'nothing' => null,
        ]);

        $this->assertNotNull($capturedContext);
        $this->assertSame(42, $capturedContext['count']);
        $this->assertTrue($capturedContext['enabled']);
        $this->assertSame(3.14, $capturedContext['ratio']);
        $this->assertNull($capturedContext['nothing']);
    }

    // =========================================================================
    // Boundary Tests (kill > vs >= mutations)
    // =========================================================================

    #[Test]
    public function testContextWithExactly50KeysIsNotTruncated(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        // Create context with exactly 50 keys (MAX_CONTEXT_KEYS)
        $context = [];
        for ($i = 0; $i < 50; $i++) {
            /** @noinspection PhpUnnecessaryCurlyVarSyntaxInspection Curly braces improve readability */
            $context["key_{$i}"] = "value_{$i}";
        }

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', $context);

        $this->assertNotNull($capturedContext);
        // All 50 user keys should be present
        $this->assertArrayHasKey('key_0', $capturedContext);
        $this->assertArrayHasKey('key_49', $capturedContext);
        // NO truncation marker should be present (exactly at limit, not over)
        $this->assertArrayNotHasKey('***TRUNCATED***', $capturedContext);
    }

    #[Test]
    public function testContextWith51KeysIsTruncated(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        // Create context with 51 keys (one over MAX_CONTEXT_KEYS)
        $context = [];
        for ($i = 0; $i < 51; $i++) {
            /** @noinspection PhpUnnecessaryCurlyVarSyntaxInspection Curly braces improve readability */
            $context["key_{$i}"] = "value_{$i}";
        }

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', $context);

        $this->assertNotNull($capturedContext);
        // Truncation marker SHOULD be present
        $this->assertArrayHasKey('***TRUNCATED***', $capturedContext);
        $this->assertSame('1 keys omitted', $capturedContext['***TRUNCATED***']);
    }

    #[Test]
    public function testStringWithExactly1000CharsIsNotTruncated(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        // Exactly 1000 characters (MAX_STRING_LENGTH)
        $exactString = str_repeat('x', 1000);

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', ['text' => $exactString]);

        $this->assertNotNull($capturedContext);
        // String should NOT be truncated (exactly at limit)
        $this->assertSame($exactString, $capturedContext['text']);
        $this->assertStringNotContainsString('***TRUNCATED***', $capturedContext['text']);
    }

    #[Test]
    public function testStringWith1001CharsIsTruncated(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        // 1001 characters (one over MAX_STRING_LENGTH)
        $longString = str_repeat('x', 1001);

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', ['text' => $longString]);

        $this->assertNotNull($capturedContext);
        // String SHOULD be truncated
        $this->assertStringContainsString('***TRUNCATED***', $capturedContext['text']);
        // First 1000 chars should be preserved
        $this->assertStringStartsWith(str_repeat('x', 1000), $capturedContext['text']);
    }

    #[Test]
    public function testMultiByteStringTruncationPreservesCharacters(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        // 1001 multi-byte characters (each is 3 bytes in UTF-8)
        $multiByteString = str_repeat('日', 1001);

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', ['text' => $multiByteString]);

        $this->assertNotNull($capturedContext);
        // Should be truncated at 1000 CHARACTERS, not bytes
        $this->assertStringContainsString('***TRUNCATED***', $capturedContext['text']);
        // Should start with 1000 Japanese characters
        $this->assertStringStartsWith(str_repeat('日', 1000), $capturedContext['text']);
    }

    #[Test]
    public function testPiiMaskingWithMatchingPattern(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        // Test email pattern in a value (not key)
        $logger->warning('Test', ['message' => 'User email is user@example.com']);

        $this->assertNotNull($capturedContext);
        // Email should be masked in the value
        $this->assertStringContainsString('***REDACTED***', $capturedContext['message']);
        $this->assertStringNotContainsString('user@example.com', $capturedContext['message']);
    }

    #[Test]
    public function testTruncationMessageShowsCorrectCount(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        // Create context with 55 keys (5 over limit)
        $context = [];
        for ($i = 0; $i < 55; $i++) {
            /** @noinspection PhpUnnecessaryCurlyVarSyntaxInspection Curly braces improve readability */
            $context["key_{$i}"] = "value_{$i}";
        }

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', $context);

        $this->assertNotNull($capturedContext);
        // Should show correct count (55 - 50 = 5)
        $this->assertSame('5 keys omitted', $capturedContext['***TRUNCATED***']);
    }

    #[Test]
    public function testTruncatedStringStartsWithOriginalContent(): void
    {
        $psrLogger = $this->createMock(LoggerInterface::class);
        $logger    = new SecurityAuditLogger($psrLogger);

        // Create a distinguishable pattern at the start
        $longString = 'START_MARKER' . str_repeat('x', 2000);

        /** @var array<string, mixed>|null $capturedContext */
        $capturedContext = null;
        $psrLogger->expects($this->once())
            ->method('warning')
            ->willReturnCallback(function (string|Stringable $message, array $context) use (&$capturedContext): void {
                $capturedContext = $context;
            });

        $logger->warning('Test', ['text' => $longString]);

        $this->assertNotNull($capturedContext);
        // Truncated string should start with the original beginning
        $this->assertStringStartsWith('START_MARKER', $capturedContext['text']);
        // And end with truncation marker
        $this->assertStringEndsWith('***TRUNCATED***', $capturedContext['text']);
    }
}
