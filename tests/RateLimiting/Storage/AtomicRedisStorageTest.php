<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting\Storage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Redis;
use RedisException;
use Zappzarapp\Security\RateLimiting\Storage\AtomicRedisStorage;
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorage;

/**
 * Tests for AtomicRedisStorage
 *
 * These tests require a Redis instance running on localhost:6379.
 * Skip these tests in CI if Redis is not available.
 */
#[CoversClass(AtomicRedisStorage::class)]
#[RequiresPhpExtension('redis')]
final class AtomicRedisStorageTest extends TestCase
{
    private ?Redis $redis = null;

    private ?AtomicRedisStorage $storage = null;

    protected function setUp(): void
    {
        if (!extension_loaded('redis')) {
            $this->markTestSkipped('Redis extension is not available');
        }

        try {
            $this->redis = new Redis();
            $connected   = @$this->redis->connect('127.0.0.1', 6379, 1.0);

            if (!$connected) {
                $this->markTestSkipped('Cannot connect to Redis on localhost:6379');
            }

            // Verify connection actually works
            $this->redis->ping();

            // Use a test-specific prefix to avoid conflicts
            $this->storage = new AtomicRedisStorage($this->redis, 'test:ratelimit:');

            // Clean up any existing test keys
            $this->cleanupTestKeys();
        } catch (RedisException $e) { // @phpstan-ignore catch.neverThrown (Redis methods can throw)
            $this->markTestSkipped('Redis server not available: ' . $e->getMessage());
        }
    }

    protected function tearDown(): void
    {
        try {
            $this->cleanupTestKeys();
            $this->redis?->close();
        } catch (RedisException) { // @phpstan-ignore catch.neverThrown (Redis methods can throw)
            // Ignore cleanup errors if Redis is not available
        }
    }

    private function cleanupTestKeys(): void
    {
        if ($this->redis === null) {
            return;
        }

        $keys = $this->redis->keys('test:ratelimit:*');
        if (is_array($keys) && $keys !== []) {
            $this->redis->del($keys);
        }
    }

    private function storage(): AtomicRedisStorage
    {
        $this->assertNotNull($this->storage, 'Storage not initialized - setUp failed?');

        return $this->storage;
    }

    private function redis(): Redis
    {
        $this->assertNotNull($this->redis, 'Redis not initialized - setUp failed?');

        return $this->redis;
    }

    #[Test]
    public function testGetReturnsNullForMissingKey(): void
    {
        $result = $this->storage()->get('nonexistent');

        $this->assertNull($result);
    }

    #[Test]
    public function testSetAndGet(): void
    {
        $data = ['tokens' => 100, 'last_refill' => time()];

        $this->storage()->set('test-key', $data, 60);
        $result = $this->storage()->get('test-key');

        $this->assertSame($data, $result);
    }

    #[Test]
    public function testDelete(): void
    {
        $this->storage()->set('delete-test', ['value' => 1], 60);
        $this->assertNotNull($this->storage()->get('delete-test'));

        $this->storage()->delete('delete-test');

        $this->assertNull($this->storage()->get('delete-test'));
    }

    #[Test]
    public function testIncrementCreatesNewKey(): void
    {
        $result = $this->storage()->increment('new-counter', 5, 60);

        $this->assertSame(5, $result);
    }

    #[Test]
    public function testIncrementExistingKey(): void
    {
        $this->storage()->increment('counter', 10, 60);
        $result = $this->storage()->increment('counter', 5, 60);

        $this->assertSame(15, $result);
    }

    #[Test]
    public function testIncrementIsAtomic(): void
    {
        // This test verifies atomicity by checking that TTL is properly set
        $this->storage()->increment('atomic-test', 1, 30);

        $ttl = $this->redis()->ttl('test:ratelimit:atomic-test');

        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(30, $ttl);
    }

    #[Test]
    public function testAtomicSlidingWindowAllowsWithinLimit(): void
    {
        $result = $this->storage()->atomicSlidingWindow(
            'sliding-test',
            windowSize: 60,
            limit: 10,
            cost: 1
        );

        $this->assertTrue($result['allowed']);
        $this->assertSame(9, $result['remaining']);
        $this->assertSame(0, $result['retryAfter']);
    }

    #[Test]
    public function testAtomicSlidingWindowDeniesWhenExceeded(): void
    {
        // Consume all allowed requests
        for ($i = 0; $i < 5; $i++) {
            $this->storage()->atomicSlidingWindow('limit-test', 60, 5, 1);
        }

        // Next request should be denied
        $result = $this->storage()->atomicSlidingWindow('limit-test', 60, 5, 1);

        $this->assertFalse($result['allowed']);
        $this->assertSame(0, $result['remaining']);
        $this->assertGreaterThan(0, $result['retryAfter']);
    }

    #[Test]
    public function testAtomicSlidingWindowWithHighCost(): void
    {
        $result = $this->storage()->atomicSlidingWindow(
            'cost-test',
            windowSize: 60,
            limit: 10,
            cost: 5
        );

        $this->assertTrue($result['allowed']);
        $this->assertSame(5, $result['remaining']);

        // Second request with same cost should be allowed
        $result2 = $this->storage()->atomicSlidingWindow('cost-test', 60, 10, 5);
        $this->assertTrue($result2['allowed']);
        $this->assertSame(0, $result2['remaining']);

        // Third request should be denied
        $result3 = $this->storage()->atomicSlidingWindow('cost-test', 60, 10, 1);
        $this->assertFalse($result3['allowed']);
    }

    #[Test]
    public function testAtomicTokenBucketAllowsWithTokens(): void
    {
        $result = $this->storage()->atomicTokenBucket(
            'bucket-test',
            bucketSize: 10,
            refillRate: 1.0,
            cost: 1,
            ttl: 60
        );

        $this->assertTrue($result['allowed']);
        $this->assertSame(9, $result['remaining']);
    }

    #[Test]
    public function testAtomicTokenBucketDeniesWhenEmpty(): void
    {
        // Consume all tokens
        for ($i = 0; $i < 5; $i++) {
            $this->storage()->atomicTokenBucket('empty-bucket', 5, 0.1, 1, 60);
        }

        // Next request should be denied
        $result = $this->storage()->atomicTokenBucket('empty-bucket', 5, 0.1, 1, 60);

        $this->assertFalse($result['allowed']);
        $this->assertGreaterThan(0, $result['retryAfter']);
    }

    #[Test]
    public function testAtomicTokenBucketWithBurst(): void
    {
        // Bucket size 10, try to consume 8 at once
        $result = $this->storage()->atomicTokenBucket('burst-test', 10, 1.0, 8, 60);

        $this->assertTrue($result['allowed']);
        $this->assertSame(2, $result['remaining']);
    }

    #[Test]
    public function testPrefixIsApplied(): void
    {
        $customStorage = new AtomicRedisStorage($this->redis(), 'custom:prefix:');
        $customStorage->set('prefixed-key', ['test' => true], 60);

        // Verify key exists with custom prefix
        $exists = $this->redis()->exists('custom:prefix:prefixed-key');
        $this->assertSame(1, $exists);

        // Clean up
        $this->redis()->del('custom:prefix:prefixed-key');
    }

    #[Test]
    public function testImplementsRateLimitStorage(): void
    {
        $this->assertInstanceOf(RateLimitStorage::class, $this->storage());
    }

    #[Test]
    public function testGetReturnsNullForInvalidJson(): void
    {
        // Store invalid JSON directly
        $this->redis()->set('test:ratelimit:invalid-json', 'not-json');

        $result = $this->storage()->get('invalid-json');

        $this->assertNull($result);
    }

    #[Test]
    public function testGetReturnsNullForNonArrayJson(): void
    {
        // Store a JSON string that is not an array
        $this->redis()->set('test:ratelimit:non-array', '"just a string"');

        $result = $this->storage()->get('non-array');

        $this->assertNull($result);
    }

    #[Test]
    public function testDeleteNonexistentKey(): void
    {
        // Should not throw
        $this->storage()->delete('nonexistent-delete-test');

        $this->assertNull($this->storage()->get('nonexistent-delete-test'));
    }

    #[Test]
    public function testSetWithComplexData(): void
    {
        $data = [
            'tokens'      => 50,
            'last_refill' => time(),
            'metadata'    => [
                'nested' => true,
            ],
        ];

        $this->storage()->set('complex-data', $data, 60);
        $result = $this->storage()->get('complex-data');

        $this->assertSame($data, $result);
    }

    #[Test]
    public function testIncrementMultipleTimes(): void
    {
        $result1 = $this->storage()->increment('multi-increment', 1, 60);
        $result2 = $this->storage()->increment('multi-increment', 2, 60);
        $result3 = $this->storage()->increment('multi-increment', 3, 60);

        $this->assertSame(1, $result1);
        $this->assertSame(3, $result2);
        $this->assertSame(6, $result3);
    }

    #[Test]
    public function testAtomicSlidingWindowResetAt(): void
    {
        $result = $this->storage()->atomicSlidingWindow(
            'reset-at-test',
            windowSize: 60,
            limit: 10,
            cost: 1
        );

        $now = time();
        $this->assertGreaterThanOrEqual($now, $result['resetAt']);
        $this->assertLessThanOrEqual($now + 60, $result['resetAt']);
    }

    #[Test]
    public function testAtomicTokenBucketResetAt(): void
    {
        $result = $this->storage()->atomicTokenBucket(
            'reset-at-bucket',
            bucketSize: 10,
            refillRate: 1.0,
            cost: 5,
            ttl: 60
        );

        $now = time();
        $this->assertGreaterThanOrEqual($now, $result['resetAt']);
    }

    #[Test]
    public function testAtomicSlidingWindowWithZeroCost(): void
    {
        $result = $this->storage()->atomicSlidingWindow(
            'zero-cost-test',
            windowSize: 60,
            limit: 10,
            cost: 0
        );

        $this->assertTrue($result['allowed']);
        $this->assertSame(10, $result['remaining']);
    }

    #[Test]
    public function testAtomicTokenBucketWithZeroCost(): void
    {
        $result = $this->storage()->atomicTokenBucket(
            'zero-cost-bucket',
            bucketSize: 10,
            refillRate: 1.0,
            cost: 0,
            ttl: 60
        );

        $this->assertTrue($result['allowed']);
        $this->assertSame(10, $result['remaining']);
    }

    #[Test]
    public function testDefaultPrefix(): void
    {
        $defaultStorage = new AtomicRedisStorage($this->redis());
        $defaultStorage->set('default-prefix-test', ['value' => 1], 60);

        // Default prefix is 'ratelimit:'
        $exists = $this->redis()->exists('ratelimit:default-prefix-test');
        $this->assertSame(1, $exists);

        // Clean up
        $this->redis()->del('ratelimit:default-prefix-test');
    }

    #[Test]
    public function testAtomicSlidingWindowCostExceedsLimit(): void
    {
        $result = $this->storage()->atomicSlidingWindow(
            'exceeds-limit',
            windowSize: 60,
            limit: 5,
            cost: 10
        );

        $this->assertFalse($result['allowed']);
        $this->assertSame(0, $result['remaining']);
    }

    #[Test]
    public function testAtomicTokenBucketCostExceedsBucket(): void
    {
        $result = $this->storage()->atomicTokenBucket(
            'exceeds-bucket',
            bucketSize: 5,
            refillRate: 1.0,
            cost: 10,
            ttl: 60
        );

        $this->assertFalse($result['allowed']);
        $this->assertGreaterThan(0, $result['retryAfter']);
    }
}
