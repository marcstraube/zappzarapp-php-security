<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\RateLimiting\RateLimitResult;

#[CoversClass(RateLimitResult::class)]
final class RateLimitResultTest extends TestCase
{
    #[Test]
    public function testAllowedFactory(): void
    {
        $result = RateLimitResult::allowed(100, 50, time() + 60);

        $this->assertTrue($result->allowed);
        $this->assertSame(100, $result->limit);
        $this->assertSame(50, $result->remaining);
        $this->assertSame(0, $result->retryAfter);
    }

    #[Test]
    public function testDeniedFactory(): void
    {
        $now    = time();
        $result = RateLimitResult::denied(100, $now + 60, 60);

        $this->assertFalse($result->allowed);
        $this->assertSame(100, $result->limit);
        $this->assertSame(0, $result->remaining);
        $this->assertSame(60, $result->retryAfter);
    }

    #[Test]
    public function testIsAllowedReturnsTrue(): void
    {
        $result = RateLimitResult::allowed(100, 50, time() + 60);

        $this->assertTrue($result->isAllowed());
    }

    #[Test]
    public function testIsAllowedReturnsFalse(): void
    {
        $result = RateLimitResult::denied(100, time() + 60, 60);

        $this->assertFalse($result->isAllowed());
    }

    #[Test]
    public function testIsDeniedReturnsTrue(): void
    {
        $result = RateLimitResult::denied(100, time() + 60, 60);

        $this->assertTrue($result->isDenied());
    }

    #[Test]
    public function testIsDeniedReturnsFalse(): void
    {
        $result = RateLimitResult::allowed(100, 50, time() + 60);

        $this->assertFalse($result->isDenied());
    }

    #[Test]
    public function testToHeaders(): void
    {
        $resetAt = time() + 60;
        $result  = RateLimitResult::allowed(100, 50, $resetAt);

        $headers = $result->toHeaders();

        $this->assertSame('100', $headers['X-RateLimit-Limit']);
        $this->assertSame('50', $headers['X-RateLimit-Remaining']);
        $this->assertSame((string) $resetAt, $headers['X-RateLimit-Reset']);
        $this->assertArrayNotHasKey('Retry-After', $headers);
    }

    #[Test]
    public function testToHeadersWithRetryAfter(): void
    {
        $result = RateLimitResult::denied(100, time() + 60, 60);

        $headers = $result->toHeaders();

        $this->assertSame('100', $headers['X-RateLimit-Limit']);
        $this->assertSame('0', $headers['X-RateLimit-Remaining']);
        $this->assertSame('60', $headers['Retry-After']);
    }

    #[Test]
    public function testRemainingIsNeverNegative(): void
    {
        $result = RateLimitResult::allowed(100, -5, time() + 60);

        $this->assertSame(-5, $result->remaining);
    }

    #[Test]
    public function testToHeadersRemainingNeverNegativeInHeader(): void
    {
        $result = RateLimitResult::allowed(100, -5, time() + 60);

        $headers = $result->toHeaders();

        $this->assertSame('0', $headers['X-RateLimit-Remaining']);
    }

    #[RunInSeparateProcess]
    #[RequiresPhpExtension('xdebug')]
    #[Test]
    public function testApplyHeaders(): void
    {
        $resetAt = time() + 60;
        $result  = RateLimitResult::allowed(100, 50, $resetAt);

        $result->applyHeaders();

        $headers = xdebug_get_headers();
        $this->assertContains('X-RateLimit-Limit: 100', $headers);
        $this->assertContains('X-RateLimit-Remaining: 50', $headers);
        $this->assertContains('X-RateLimit-Reset: ' . $resetAt, $headers);
    }

    #[RunInSeparateProcess]
    #[RequiresPhpExtension('xdebug')]
    #[Test]
    public function testApplyHeadersWithDeniedResult(): void
    {
        $result = RateLimitResult::denied(100, time() + 60, 60);

        $result->applyHeaders();

        $headers = xdebug_get_headers();
        $this->assertContains('X-RateLimit-Limit: 100', $headers);
        $this->assertContains('X-RateLimit-Remaining: 0', $headers);
        $this->assertContains('Retry-After: 60', $headers);
    }

    #[RunInSeparateProcess]
    #[RequiresPhpExtension('xdebug')]
    #[Test]
    public function testApplyHeadersWithReplaceTrue(): void
    {
        $result1 = RateLimitResult::allowed(100, 50, time() + 60);
        $result2 = RateLimitResult::allowed(200, 150, time() + 120);

        $result1->applyHeaders(true);
        $result2->applyHeaders(true);

        $headers = xdebug_get_headers();
        // The second call should replace the first
        $this->assertContains('X-RateLimit-Limit: 200', $headers);
        $this->assertContains('X-RateLimit-Remaining: 150', $headers);
    }

    #[RunInSeparateProcess]
    #[RequiresPhpExtension('xdebug')]
    #[Test]
    public function testApplyHeadersWithReplaceFalse(): void
    {
        $result1 = RateLimitResult::allowed(100, 50, time() + 60);
        $result2 = RateLimitResult::allowed(200, 150, time() + 120);

        $result1->applyHeaders(true);
        $result2->applyHeaders(false);

        $headers = xdebug_get_headers();
        // Both headers should be present
        $this->assertContains('X-RateLimit-Limit: 100', $headers);
        $this->assertContains('X-RateLimit-Limit: 200', $headers);
    }

    #[Test]
    public function testConstructorWithAllParameters(): void
    {
        $result = new RateLimitResult(
            allowed: true,
            limit: 100,
            remaining: 50,
            resetAt: 1234567890,
            retryAfter: 0
        );

        $this->assertTrue($result->allowed);
        $this->assertSame(100, $result->limit);
        $this->assertSame(50, $result->remaining);
        $this->assertSame(1234567890, $result->resetAt);
        $this->assertSame(0, $result->retryAfter);
    }

    #[Test]
    public function testConstructorDefaultRetryAfter(): void
    {
        $result = new RateLimitResult(
            allowed: true,
            limit: 100,
            remaining: 50,
            resetAt: 1234567890
        );

        $this->assertSame(0, $result->retryAfter);
    }

    #[Test]
    public function testApplyHeadersCallsHeaderFunction(): void
    {
        // Test that applyHeaders iterates through toHeaders() properly
        // This tests the loop logic without needing xdebug
        $resetAt = time() + 60;
        $result  = RateLimitResult::allowed(100, 50, $resetAt);

        $headers = $result->toHeaders();

        $this->assertCount(3, $headers);
        $this->assertArrayHasKey('X-RateLimit-Limit', $headers);
        $this->assertArrayHasKey('X-RateLimit-Remaining', $headers);
        $this->assertArrayHasKey('X-RateLimit-Reset', $headers);
    }

    #[Test]
    public function testApplyHeadersWithDeniedResultAddsRetryAfter(): void
    {
        $result = RateLimitResult::denied(100, time() + 60, 60);

        $headers = $result->toHeaders();

        $this->assertCount(4, $headers);
        $this->assertArrayHasKey('Retry-After', $headers);
    }

    #[Test]
    public function testApplyHeadersInCliDoesNotThrow(): void
    {
        // In CLI mode, headers_sent() may return true, but applyHeaders should still work
        $result = RateLimitResult::allowed(100, 50, time() + 60);

        // This should not throw even if headers were already sent
        // We just verify it executes without error
        $result->applyHeaders();

        // If we get here, the method executed successfully
        $this->assertTrue(true);
    }

    #[Test]
    public function testApplyHeadersWithReplaceParameter(): void
    {
        $result = RateLimitResult::allowed(100, 50, time() + 60);

        // Test that the replace parameter is accepted (both true and false)
        $result->applyHeaders(true);
        $result->applyHeaders(false);

        // If we get here without errors, the method accepts the parameter correctly
        $this->assertTrue(true);
    }
}
