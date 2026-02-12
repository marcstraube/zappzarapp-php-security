<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting\Storage;

use Memcached;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\RateLimiting\Storage\MemcachedStorage;
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorage;

/**
 * @psalm-suppress UndefinedClass (Memcached extension not always installed)
 */

#[CoversClass(MemcachedStorage::class)]
#[RequiresPhpExtension('memcached')]
final class MemcachedStorageTest extends TestCase
{
    public function testImplementsInterface(): void
    {
        $memcached = $this->createStub(Memcached::class);
        $storage   = new MemcachedStorage($memcached);

        $this->assertInstanceOf(RateLimitStorage::class, $storage);
    }

    public function testGetReturnsNullWhenKeyNotFound(): void
    {
        $memcached = $this->createStub(Memcached::class);
        $memcached->method('get')->willReturn(false);

        $storage = new MemcachedStorage($memcached);

        $this->assertNull($storage->get('nonexistent'));
    }

    public function testGetReturnsData(): void
    {
        $data      = ['count' => 5, 'window' => 60];
        $memcached = $this->createStub(Memcached::class);
        $memcached->method('get')->willReturn($data);

        $storage = new MemcachedStorage($memcached);

        $this->assertSame($data, $storage->get('key'));
    }

    public function testGetWithPrefix(): void
    {
        $memcached = $this->createMock(Memcached::class);
        $memcached->expects($this->once())
            ->method('get')
            ->with('custom:mykey')
            ->willReturn(false);

        $storage = new MemcachedStorage($memcached, 'custom:');
        $storage->get('mykey');
    }

    public function testSetStoresData(): void
    {
        $data      = ['count' => 10];
        $memcached = $this->createMock(Memcached::class);
        $memcached->expects($this->once())
            ->method('set')
            ->with('ratelimit:key', $data, 60);

        $storage = new MemcachedStorage($memcached);
        $storage->set('key', $data, 60);
    }

    public function testDeleteRemovesKey(): void
    {
        $memcached = $this->createMock(Memcached::class);
        $memcached->expects($this->once())
            ->method('delete')
            ->with('ratelimit:key');

        $storage = new MemcachedStorage($memcached);
        $storage->delete('key');
    }

    public function testIncrementExistingKey(): void
    {
        $memcached = $this->createMock(Memcached::class);
        $memcached->expects($this->once())
            ->method('increment')
            ->with('ratelimit:key', 1)
            ->willReturn(5);

        $storage = new MemcachedStorage($memcached);
        $result  = $storage->increment('key', 1, 60);

        $this->assertSame(5, $result);
    }

    public function testIncrementNewKeyWithAdd(): void
    {
        $memcached = $this->createMock(Memcached::class);
        $memcached->expects($this->once())
            ->method('increment')
            ->willReturn(false);
        $memcached->expects($this->once())
            ->method('add')
            ->with('ratelimit:key', 1, 60)
            ->willReturn(true);

        $storage = new MemcachedStorage($memcached);
        $result  = $storage->increment('key', 1, 60);

        $this->assertSame(1, $result);
    }

    public function testIncrementWithRaceCondition(): void
    {
        $memcached = $this->createMock(Memcached::class);
        // First increment fails (key doesn't exist)
        $memcached->expects($this->exactly(2))
            ->method('increment')
            ->willReturnOnConsecutiveCalls(false, 2);
        // add fails (another process created the key)
        $memcached->expects($this->once())
            ->method('add')
            ->willReturn(false);

        $storage = new MemcachedStorage($memcached);
        $result  = $storage->increment('key', 1, 60);

        $this->assertSame(2, $result);
    }
}
