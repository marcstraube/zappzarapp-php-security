<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Storage;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\Storage\RedisCsrfStorage;

#[CoversClass(RedisCsrfStorage::class)]
final class RedisCsrfStorageTest extends TestCase
{
    #[Test]
    public function testStoreWithTtlUsesSetex(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('setex')
            ->with('csrf:session1', 3600, 'token-value');
        $redis->expects($this->never())->method('set');

        $storage = new RedisCsrfStorage($redis);
        $storage->store('session1', 'token-value', 3600);
    }

    #[Test]
    public function testStoreWithoutTtlUsesSet(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('set')
            ->with('csrf:session1', 'token-value');
        $redis->expects($this->never())->method('setex');

        $storage = new RedisCsrfStorage($redis);
        $storage->store('session1', 'token-value');
    }

    #[Test]
    public function testStoreWithZeroTtlUsesSetWithoutExpiry(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('set')
            ->with('csrf:session1', 'token-value');
        $redis->expects($this->never())->method('setex');

        $storage = new RedisCsrfStorage($redis);
        $storage->store('session1', 'token-value', 0);
    }

    #[Test]
    public function testStoreUsesCustomPrefix(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('setex')
            ->with('app:session1', 3600, 'token-value');

        $storage = new RedisCsrfStorage($redis, 'app:');
        $storage->store('session1', 'token-value', 3600);
    }

    #[AllowMockObjectsWithoutExpectations]
    #[Test]
    public function testRetrieveReturnsNullWhenMissingFalse(): void
    {
        $redis = $this->createMockRedis();
        $redis->method('get')->willReturn(false);

        $storage = new RedisCsrfStorage($redis);

        $this->assertNull($storage->retrieve('session1'));
    }

    #[AllowMockObjectsWithoutExpectations]
    #[Test]
    public function testRetrieveReturnsNullWhenMissingNull(): void
    {
        $redis = $this->createMockRedis();
        $redis->method('get')->willReturn(null);

        $storage = new RedisCsrfStorage($redis);

        $this->assertNull($storage->retrieve('session1'));
    }

    #[Test]
    public function testRetrieveReturnsToken(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('get')
            ->with('csrf:session1')
            ->willReturn('token-value');

        $storage = new RedisCsrfStorage($redis);

        $this->assertSame('token-value', $storage->retrieve('session1'));
    }

    #[Test]
    public function testRemoveDeletesPrefixedKey(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('del')
            ->with('csrf:session1');

        $storage = new RedisCsrfStorage($redis);
        $storage->remove('session1');
    }

    #[AllowMockObjectsWithoutExpectations]
    #[Test]
    public function testHasReturnsTrueWhenTokenExists(): void
    {
        $redis = $this->createMockRedis();
        $redis->method('get')->willReturn('token-value');

        $storage = new RedisCsrfStorage($redis);

        $this->assertTrue($storage->has('session1'));
    }

    #[AllowMockObjectsWithoutExpectations]
    #[Test]
    public function testHasReturnsFalseWhenTokenMissing(): void
    {
        $redis = $this->createMockRedis();
        $redis->method('get')->willReturn(false);

        $storage = new RedisCsrfStorage($redis);

        $this->assertFalse($storage->has('session1'));
    }

    #[Test]
    public function testClearDeletesAllMatchingKeys(): void
    {
        $keys  = ['csrf:session1', 'csrf:session2'];
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('keys')
            ->with('csrf:*')
            ->willReturn($keys);
        $redis->expects($this->once())
            ->method('del')
            ->with($keys);

        $storage = new RedisCsrfStorage($redis);
        $storage->clear();
    }

    #[Test]
    public function testClearDoesNothingWhenNoKeysMatch(): void
    {
        $redis = $this->createMockRedis();
        $redis->method('keys')->willReturn([]);
        $redis->expects($this->never())->method('del');

        $storage = new RedisCsrfStorage($redis);
        $storage->clear();
    }

    /**
     * @return MockObject
     */
    private function createMockRedis(): MockObject
    {
        return $this->createMock(RedisCsrfMockInterface::class);
    }
}

/**
 * Interface for Redis client mock
 *
 * @internal Test interface only
 *
 * @psalm-suppress PossiblyUnusedMethod
 */
interface RedisCsrfMockInterface
{
    public function get(string $key): string|false|null;

    public function set(string $key, string $value): bool;

    public function setex(string $key, int $ttl, string $value): bool;

    /**
     * @param string|list<string> $key
     */
    public function del(string|array $key): int;

    /**
     * @return list<string>
     */
    public function keys(string $pattern): array;
}
