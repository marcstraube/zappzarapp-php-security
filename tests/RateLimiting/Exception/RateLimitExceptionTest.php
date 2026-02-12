<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\RateLimiting\Exception\RateLimitException;

#[CoversClass(RateLimitException::class)]
final class RateLimitExceptionTest extends TestCase
{
    public function testExtendsRuntimeException(): void
    {
        $exception = new RateLimitException(60, 100, 0);

        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    public function testMessage(): void
    {
        $exception = new RateLimitException(60, 100, 0);

        $this->assertSame('Rate limit exceeded. Retry after 60 seconds.', $exception->getMessage());
    }

    public function testMessageWithDifferentRetryAfter(): void
    {
        $exception = new RateLimitException(120, 100, 0);

        $this->assertSame('Rate limit exceeded. Retry after 120 seconds.', $exception->getMessage());
    }

    public function testRetryAfter(): void
    {
        $exception = new RateLimitException(60, 100, 5);

        $this->assertSame(60, $exception->retryAfter());
    }

    public function testLimit(): void
    {
        $exception = new RateLimitException(60, 100, 5);

        $this->assertSame(100, $exception->limit());
    }

    public function testRemaining(): void
    {
        $exception = new RateLimitException(60, 100, 5);

        $this->assertSame(5, $exception->remaining());
    }

    public function testRemainingIsZeroWhenExceeded(): void
    {
        $exception = new RateLimitException(60, 100, 0);

        $this->assertSame(0, $exception->remaining());
    }

    public function testExceededFactory(): void
    {
        $exception = RateLimitException::exceeded(30, 50);

        $this->assertSame(30, $exception->retryAfter());
        $this->assertSame(50, $exception->limit());
        $this->assertSame(0, $exception->remaining());
    }

    public function testExceededFactoryMessage(): void
    {
        $exception = RateLimitException::exceeded(30, 50);

        $this->assertSame('Rate limit exceeded. Retry after 30 seconds.', $exception->getMessage());
    }

    public function testExceededFactoryWithZeroRetryAfter(): void
    {
        $exception = RateLimitException::exceeded(0, 100);

        $this->assertSame(0, $exception->retryAfter());
        $this->assertSame('Rate limit exceeded. Retry after 0 seconds.', $exception->getMessage());
    }

    public function testExceededFactoryWithLargeValues(): void
    {
        $exception = RateLimitException::exceeded(3600, 10000);

        $this->assertSame(3600, $exception->retryAfter());
        $this->assertSame(10000, $exception->limit());
        $this->assertSame(0, $exception->remaining());
    }

    public function testConstructorWithNegativeValues(): void
    {
        // Edge case: negative values should be accepted (though not recommended)
        $exception = new RateLimitException(-1, -1, -1);

        $this->assertSame(-1, $exception->retryAfter());
        $this->assertSame(-1, $exception->limit());
        $this->assertSame(-1, $exception->remaining());
    }

    public function testConstructorWithZeroValues(): void
    {
        $exception = new RateLimitException(0, 0, 0);

        $this->assertSame(0, $exception->retryAfter());
        $this->assertSame(0, $exception->limit());
        $this->assertSame(0, $exception->remaining());
    }
}
