<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\RateLimiting\Exception\StorageException;

#[CoversClass(StorageException::class)]
final class StorageExceptionTest extends TestCase
{
    #[Test]
    public function testExtendsRuntimeException(): void
    {
        $exception = new StorageException('Test message');

        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    #[Test]
    public function testConnectionFailedFactory(): void
    {
        $exception = StorageException::connectionFailed('Connection refused');

        $this->assertSame(
            'Rate limit storage connection failed: Connection refused',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testConnectionFailedWithEmptyReason(): void
    {
        $exception = StorageException::connectionFailed('');

        $this->assertSame(
            'Rate limit storage connection failed: ',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testConnectionFailedWithDetailedReason(): void
    {
        $exception = StorageException::connectionFailed('Could not connect to Redis at 127.0.0.1:6379');

        $this->assertSame(
            'Rate limit storage connection failed: Could not connect to Redis at 127.0.0.1:6379',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testReadFailedFactory(): void
    {
        $exception = StorageException::readFailed('rate_limit:user:123', 'Key not found');

        $this->assertSame(
            'Failed to read rate limit for "rate_limit:user:123": Key not found',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testReadFailedWithEmptyKey(): void
    {
        $exception = StorageException::readFailed('', 'Empty key');

        $this->assertSame(
            'Failed to read rate limit for "": Empty key',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testReadFailedWithEmptyReason(): void
    {
        $exception = StorageException::readFailed('key', '');

        $this->assertSame(
            'Failed to read rate limit for "key": ',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testReadFailedWithSpecialCharacters(): void
    {
        $exception = StorageException::readFailed('rate_limit:ip:192.168.1.1', 'Timeout');

        $this->assertSame(
            'Failed to read rate limit for "rate_limit:ip:192.168.1.1": Timeout',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testWriteFailedFactory(): void
    {
        $exception = StorageException::writeFailed('rate_limit:user:123', 'Disk full');

        $this->assertSame(
            'Failed to write rate limit for "rate_limit:user:123": Disk full',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testWriteFailedWithEmptyKey(): void
    {
        $exception = StorageException::writeFailed('', 'Invalid key');

        $this->assertSame(
            'Failed to write rate limit for "": Invalid key',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testWriteFailedWithEmptyReason(): void
    {
        $exception = StorageException::writeFailed('key', '');

        $this->assertSame(
            'Failed to write rate limit for "key": ',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testWriteFailedWithDetailedReason(): void
    {
        $exception = StorageException::writeFailed(
            'bucket:api:abc123',
            'Redis cluster node is down'
        );

        $this->assertSame(
            'Failed to write rate limit for "bucket:api:abc123": Redis cluster node is down',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testDirectConstruction(): void
    {
        $exception = new StorageException('Custom storage error');

        $this->assertSame('Custom storage error', $exception->getMessage());
    }

    #[Test]
    public function testExceptionCanBeThrown(): void
    {
        $this->expectException(StorageException::class);
        $this->expectExceptionMessage('Rate limit storage connection failed: Test');

        throw StorageException::connectionFailed('Test');
    }

    #[Test]
    public function testExceptionCanBeCaught(): void
    {
        $caught = false;

        try {
            throw StorageException::readFailed('key', 'reason');
        } catch (StorageException $e) {
            $caught = true;
            $this->assertStringContainsString('key', $e->getMessage());
            $this->assertStringContainsString('reason', $e->getMessage());
        }

        $this->assertTrue($caught);
    }

    #[Test]
    public function testExceptionChaining(): void
    {
        $previous  = new RuntimeException('Original error');
        $exception = new StorageException('Wrapped error', 0, $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }
}
