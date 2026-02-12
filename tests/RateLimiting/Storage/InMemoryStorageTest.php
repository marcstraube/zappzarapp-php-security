<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting\Storage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\RateLimiting\Storage\InMemoryStorage;
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorage;

#[CoversClass(InMemoryStorage::class)]
final class InMemoryStorageTest extends TestCase
{
    private InMemoryStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();
    }

    public function testImplementsRateLimitStorage(): void
    {
        $this->assertInstanceOf(RateLimitStorage::class, $this->storage);
    }

    public function testGetReturnsNullForMissingKey(): void
    {
        $this->assertNull($this->storage->get('nonexistent'));
    }

    public function testSetAndGet(): void
    {
        $this->storage->set('key1', ['count' => 5], 60);

        $result = $this->storage->get('key1');

        $this->assertSame(['count' => 5], $result);
    }

    public function testDelete(): void
    {
        $this->storage->set('key1', ['count' => 5], 60);
        $this->storage->delete('key1');

        $this->assertNull($this->storage->get('key1'));
    }

    public function testDeleteNonexistentKey(): void
    {
        $this->storage->delete('nonexistent');

        $this->assertNull($this->storage->get('nonexistent'));
    }

    public function testIncrement(): void
    {
        $result = $this->storage->increment('counter', 1, 60);

        $this->assertSame(1, $result);
    }

    public function testIncrementExistingCounter(): void
    {
        $this->storage->increment('counter', 5, 60);
        $result = $this->storage->increment('counter', 3, 60);

        $this->assertSame(8, $result);
    }

    public function testIncrementWithDifferentAmounts(): void
    {
        $this->storage->increment('counter', 10, 60);
        $this->storage->increment('counter', 20, 60);
        $result = $this->storage->increment('counter', 5, 60);

        $this->assertSame(35, $result);
    }

    public function testMultipleKeys(): void
    {
        $this->storage->set('key1', ['value' => 1], 60);
        $this->storage->set('key2', ['value' => 2], 60);
        $this->storage->set('key3', ['value' => 3], 60);

        $this->assertSame(['value' => 1], $this->storage->get('key1'));
        $this->assertSame(['value' => 2], $this->storage->get('key2'));
        $this->assertSame(['value' => 3], $this->storage->get('key3'));
    }

    public function testOverwriteExistingKey(): void
    {
        $this->storage->set('key1', ['value' => 1], 60);
        $this->storage->set('key1', ['value' => 2], 60);

        $this->assertSame(['value' => 2], $this->storage->get('key1'));
    }

    public function testClear(): void
    {
        $this->storage->set('key1', ['value' => 1], 60);
        $this->storage->set('key2', ['value' => 2], 60);
        $this->storage->increment('counter1', 5, 60);

        $this->storage->clear();

        $this->assertNull($this->storage->get('key1'));
        $this->assertNull($this->storage->get('key2'));
        $this->assertSame(0, $this->storage->count());
    }

    public function testClearOnEmptyStorage(): void
    {
        $this->storage->clear();

        $this->assertSame(0, $this->storage->count());
    }

    public function testCount(): void
    {
        $this->assertSame(0, $this->storage->count());

        $this->storage->set('key1', ['value' => 1], 60);
        $this->assertSame(1, $this->storage->count());

        $this->storage->set('key2', ['value' => 2], 60);
        $this->assertSame(2, $this->storage->count());
    }

    public function testCountIncludesCounters(): void
    {
        $this->storage->set('key1', ['value' => 1], 60);
        $this->storage->increment('counter1', 5, 60);

        $this->assertSame(2, $this->storage->count());
    }

    public function testCountAfterDelete(): void
    {
        $this->storage->set('key1', ['value' => 1], 60);
        $this->storage->set('key2', ['value' => 2], 60);

        $this->storage->delete('key1');

        $this->assertSame(1, $this->storage->count());
    }

    public function testDeleteRemovesBothDataAndCounter(): void
    {
        $this->storage->set('key1', ['value' => 1], 60);
        $this->storage->increment('key1', 5, 60);

        $this->storage->delete('key1');

        $this->assertNull($this->storage->get('key1'));
        // Counter for same key should also be deleted
        $newValue = $this->storage->increment('key1', 1, 60);
        $this->assertSame(1, $newValue);
    }

    public function testGetWithZeroTtlReturnsNullAfterExpiry(): void
    {
        // Set with 0 TTL (already expired)
        $this->storage->set('key1', ['value' => 1], 0);

        // Sleep briefly to ensure time() moves
        usleep(1100000); // 1.1 seconds

        $this->assertNull($this->storage->get('key1'));
    }

    public function testCounterExpiresCorrectly(): void
    {
        // Set with 0 TTL (already expired)
        $this->storage->increment('counter1', 5, 0);

        // Sleep briefly to ensure time() moves
        usleep(1100000); // 1.1 seconds

        // After expiry, a new increment should start fresh
        $result = $this->storage->increment('counter1', 1, 60);
        $this->assertSame(1, $result);
    }

    public function testCleanupRemovesExpiredData(): void
    {
        // Set with 0 TTL (already expired)
        $this->storage->set('key1', ['value' => 1], 0);
        $this->storage->set('key2', ['value' => 2], 60);
        $this->storage->increment('counter1', 5, 0);
        $this->storage->increment('counter2', 10, 60);

        // Sleep briefly to ensure time() moves
        usleep(1100000); // 1.1 seconds

        // Trigger cleanup via get()
        $this->assertNull($this->storage->get('key1'));
        $this->assertSame(['value' => 2], $this->storage->get('key2'));
    }

    public function testCleanupRemovesMultipleExpiredEntries(): void
    {
        // Set multiple entries with 0 TTL (already expired)
        $this->storage->set('key1', ['value' => 1], 0);
        $this->storage->set('key2', ['value' => 2], 0);
        $this->storage->increment('counter1', 5, 0);
        $this->storage->increment('counter2', 10, 0);

        // Sleep briefly to ensure time() moves
        usleep(1100000); // 1.1 seconds

        // Trigger cleanup via get() on a non-existent key
        $this->assertNull($this->storage->get('nonexistent'));

        // Verify all expired entries are cleaned up
        // After cleanup, counters should be reset when accessed
        $result = $this->storage->increment('counter1', 1, 60);
        $this->assertSame(1, $result);
    }
}
