<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting\Storage;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorage;
use Zappzarapp\Security\RateLimiting\Storage\RedisStorage;

/**
 * @phpstan-type RedisMock MockObject&object{get: mixed, setex: mixed, del: mixed, incrBy: mixed, expire: mixed}
 */
#[CoversClass(RedisStorage::class)]
final class RedisStorageTest extends TestCase
{
    #[AllowMockObjectsWithoutExpectations]
    public function testImplementsInterface(): void
    {
        $redis   = $this->createMockRedis();
        $storage = new RedisStorage($redis);

        $this->assertInstanceOf(RateLimitStorage::class, $storage);
    }

    #[AllowMockObjectsWithoutExpectations]
    public function testGetReturnsNullWhenKeyNotFound(): void
    {
        $redis = $this->createMockRedis();
        $redis->method('get')->willReturn(false);

        $storage = new RedisStorage($redis);

        $this->assertNull($storage->get('nonexistent'));
    }

    #[AllowMockObjectsWithoutExpectations]
    public function testGetReturnsDecodedData(): void
    {
        $data  = ['count' => 5, 'window' => 60];
        $redis = $this->createMockRedis();
        $redis->method('get')->willReturn(json_encode($data));

        $storage = new RedisStorage($redis);

        $this->assertSame($data, $storage->get('key'));
    }

    public function testGetWithPrefix(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('get')
            ->with('custom:mykey')
            ->willReturn(null);

        $storage = new RedisStorage($redis, 'custom:');
        $storage->get('mykey');
    }

    public function testSetEncodesAndStoresData(): void
    {
        $data  = ['count' => 10];
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('setex')
            ->with('ratelimit:key', 60, json_encode($data));

        $storage = new RedisStorage($redis);
        $storage->set('key', $data, 60);
    }

    public function testDeleteRemovesKey(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('del')
            ->with('ratelimit:key');

        $storage = new RedisStorage($redis);
        $storage->delete('key');
    }

    public function testIncrementUsesAtomicLuaScript(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('eval')
            ->with(
                $this->stringContains('INCRBY'),
                ['ratelimit:key', 1, 60],
                1
            )
            ->willReturn(1);

        $storage = new RedisStorage($redis);
        $result  = $storage->increment('key', 1, 60);

        $this->assertSame(1, $result);
    }

    public function testIncrementReturnsExistingValue(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('eval')
            ->willReturn(5);

        $storage = new RedisStorage($redis);
        $result  = $storage->increment('key', 1, 60);

        $this->assertSame(5, $result);
    }

    public function testIncrementWithCustomAmount(): void
    {
        $redis = $this->createMockRedis();
        $redis->expects($this->once())
            ->method('eval')
            ->with(
                $this->stringContains('INCRBY'),
                ['ratelimit:key', 10, 60],
                1
            )
            ->willReturn(10);

        $storage = new RedisStorage($redis);
        $result  = $storage->increment('key', 10, 60);

        $this->assertSame(10, $result);
    }

    /**
     * @return MockObject
     */
    private function createMockRedis(): MockObject
    {
        return $this->createMock(RedisMockInterface::class);
    }
}

/**
 * Interface for Redis client mock
 *
 * @internal Test interface only
 * @psalm-suppress PossiblyUnusedMethod
 */
interface RedisMockInterface
{
    public function get(string $key): string|false|null;

    public function setex(string $key, int $ttl, string $value): bool;

    public function del(string $key): int;

    public function incrBy(string $key, int $amount): int;

    public function expire(string $key, int $ttl): bool;

    /**
     * Execute Lua script atomically
     *
     * @param string $script The Lua script
     * @param array<string|int> $args Arguments (keys + values)
     * @param int $numKeys Number of keys in args
     *
     * @return mixed
     */
    public function eval(string $script, array $args, int $numKeys): mixed;
}
