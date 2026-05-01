<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\RateLimiting\Storage;

use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\RateLimiting\Exception\StorageException;
use Zappzarapp\Security\RateLimiting\Storage\PdoStorage;
use Zappzarapp\Security\RateLimiting\Storage\RateLimitStorage;

#[CoversClass(PdoStorage::class)]
#[RequiresPhpExtension('pdo_sqlite')]
final class PdoStorageTest extends TestCase
{
    private PDO $pdo;

    private PdoStorage $storage;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:', null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);

        $this->pdo->exec(sprintf(PdoStorage::SCHEMA['sqlite'], 'rate_limits', 'rate_limits', 'rate_limits'));

        $this->storage = new PdoStorage($this->pdo);
    }

    #[Test]
    public function testImplementsRateLimitStorage(): void
    {
        $this->assertInstanceOf(RateLimitStorage::class, $this->storage);
    }

    #[Test]
    public function testGetReturnsNullForMissingKey(): void
    {
        $this->assertNull($this->storage->get('nonexistent'));
    }

    #[Test]
    public function testSetAndGet(): void
    {
        $this->storage->set('key1', ['count' => 5], 60);

        $result = $this->storage->get('key1');

        $this->assertSame(['count' => 5], $result);
    }

    #[Test]
    public function testSetOverwritesExistingKey(): void
    {
        $this->storage->set('key1', ['count' => 5], 60);
        $this->storage->set('key1', ['count' => 10], 60);

        $result = $this->storage->get('key1');

        $this->assertSame(['count' => 10], $result);
    }

    #[Test]
    public function testDelete(): void
    {
        $this->storage->set('key1', ['count' => 5], 60);
        $this->storage->delete('key1');

        $this->assertNull($this->storage->get('key1'));
    }

    #[Test]
    public function testDeleteNonexistentKeyDoesNotThrow(): void
    {
        $this->storage->delete('nonexistent');

        $this->assertNull($this->storage->get('nonexistent'));
    }

    #[Test]
    public function testGetReturnsNullForExpiredKey(): void
    {
        $this->storage->set('expired', ['count' => 1], 1);

        // Manually expire the entry
        $stmt = $this->pdo->prepare('UPDATE rate_limits SET "expires_at" = ? WHERE "key" = ?');
        $stmt->execute([time() - 1, 'ratelimit:expired']);

        $this->assertNull($this->storage->get('expired'));
    }

    #[Test]
    public function testGetDeletesExpiredEntry(): void
    {
        $this->storage->set('expired', ['count' => 1], 1);

        $stmt = $this->pdo->prepare('UPDATE rate_limits SET "expires_at" = ? WHERE "key" = ?');
        $stmt->execute([time() - 1, 'ratelimit:expired']);

        $this->storage->get('expired');

        // Verify the row was cleaned up
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM rate_limits WHERE "key" = ?');
        $stmt->execute(['ratelimit:expired']);

        $this->assertSame(0, (int) $stmt->fetchColumn());
    }

    #[Test]
    public function testIncrementCreatesNewKey(): void
    {
        $result = $this->storage->increment('counter', 1, 60);

        $this->assertSame(1, $result);
    }

    #[Test]
    public function testIncrementExistingKey(): void
    {
        $this->storage->increment('counter', 5, 60);
        $result = $this->storage->increment('counter', 3, 60);

        $this->assertSame(8, $result);
    }

    #[Test]
    public function testIncrementByDifferentAmounts(): void
    {
        $this->storage->increment('counter', 1, 60);
        $this->storage->increment('counter', 2, 60);
        $result = $this->storage->increment('counter', 7, 60);

        $this->assertSame(10, $result);
    }

    #[Test]
    public function testGetReturnsNullAtExactExpiry(): void
    {
        $this->storage->set('boundary', ['count' => 1], 60);

        // Set expires_at to exactly now — should be treated as expired
        $stmt = $this->pdo->prepare('UPDATE rate_limits SET "expires_at" = ? WHERE "key" = ?');
        $stmt->execute([time(), 'ratelimit:boundary']);

        $this->assertNull($this->storage->get('boundary'));
    }

    #[Test]
    public function testIncrementResetsKeyAtExactExpiry(): void
    {
        $this->storage->increment('counter', 5, 60);

        // Set expires_at to exactly now — should be treated as expired
        $stmt = $this->pdo->prepare('UPDATE rate_limits SET "expires_at" = ? WHERE "key" = ?');
        $stmt->execute([time(), 'ratelimit:counter']);

        $result = $this->storage->increment('counter', 1, 60);

        $this->assertSame(1, $result);
    }

    #[Test]
    public function testIncrementResetsExpiredKey(): void
    {
        $this->storage->increment('counter', 5, 60);

        // Manually expire the entry
        $stmt = $this->pdo->prepare('UPDATE rate_limits SET "expires_at" = ? WHERE "key" = ?');
        $stmt->execute([time() - 1, 'ratelimit:counter']);

        $result = $this->storage->increment('counter', 1, 60);

        $this->assertSame(1, $result);
    }

    #[Test]
    public function testCleanupRemovesExpiredEntries(): void
    {
        $this->storage->set('active', ['count' => 1], 3600);
        $this->storage->set('expired1', ['count' => 1], 1);
        $this->storage->set('expired2', ['count' => 1], 1);

        // Manually expire two entries
        $stmt = $this->pdo->prepare('UPDATE rate_limits SET "expires_at" = ? WHERE "key" IN (?, ?)');
        $stmt->execute([time() - 1, 'ratelimit:expired1', 'ratelimit:expired2']);

        $deleted = $this->storage->cleanup();

        $this->assertSame(2, $deleted);
        $this->assertNotNull($this->storage->get('active'));
        $this->assertNull($this->storage->get('expired1'));
        $this->assertNull($this->storage->get('expired2'));
    }

    #[Test]
    public function testCleanupReturnsZeroWhenNothingExpired(): void
    {
        $this->storage->set('active', ['count' => 1], 3600);

        $deleted = $this->storage->cleanup();

        $this->assertSame(0, $deleted);
    }

    #[Test]
    public function testPrefixIsApplied(): void
    {
        $storage = new PdoStorage($this->pdo, 'rate_limits', 'custom:');
        $storage->set('key1', ['count' => 1], 60);

        $stmt = $this->pdo->prepare('SELECT "key" FROM rate_limits');
        $stmt->execute();

        /** @var string $storedKey */
        $storedKey = $stmt->fetchColumn();

        $this->assertSame('custom:key1', $storedKey);
    }

    #[Test]
    public function testCustomTableName(): void
    {
        $this->pdo->exec(sprintf(PdoStorage::SCHEMA['sqlite'], 'custom_table', 'custom_table', 'custom_table'));

        $storage = new PdoStorage($this->pdo, 'custom_table');
        $storage->set('key1', ['count' => 1], 60);

        $result = $storage->get('key1');

        $this->assertSame(['count' => 1], $result);
    }

    #[Test]
    public function testJsonRoundTrip(): void
    {
        $data = [
            'count'  => 42,
            'tokens' => 3.14,
            'nested' => ['a' => 'b'],
            'active' => true,
        ];

        $this->storage->set('complex', $data, 60);
        $result = $this->storage->get('complex');

        $this->assertSame($data, $result);
    }

    #[Test]
    public function testGetReturnsNullForInvalidJson(): void
    {
        // Manually insert invalid JSON
        $stmt = $this->pdo->prepare(
            'INSERT INTO rate_limits ("key", "data", "expires_at") VALUES (?, ?, ?)',
        );
        $stmt->execute(['ratelimit:bad', 'not-json', time() + 60]);

        $this->assertNull($this->storage->get('bad'));
    }

    #[Test]
    public function testSetThrowsStorageExceptionOnEncodingFailure(): void
    {
        $this->expectException(StorageException::class);

        // Resources cannot be JSON-encoded
        $resource = fopen('php://memory', 'r');
        $this->storage->set('key', ['value' => $resource], 60);
    }

    #[Test]
    public function testSchemaConstantContainsAllDrivers(): void
    {
        $this->assertArrayHasKey('mysql', PdoStorage::SCHEMA);
        $this->assertArrayHasKey('pgsql', PdoStorage::SCHEMA);
        $this->assertArrayHasKey('sqlite', PdoStorage::SCHEMA);
    }

    #[Test]
    public function testMultipleKeysAreIndependent(): void
    {
        $this->storage->set('key1', ['count' => 1], 60);
        $this->storage->set('key2', ['count' => 2], 60);

        $this->storage->delete('key1');

        $this->assertNull($this->storage->get('key1'));
        $this->assertSame(['count' => 2], $this->storage->get('key2'));
    }

    #[Test]
    public function testIncrementMultipleKeysIndependently(): void
    {
        $this->storage->increment('a', 1, 60);
        $this->storage->increment('b', 10, 60);
        $this->storage->increment('a', 2, 60);

        $this->assertSame(3, $this->storage->increment('a', 0, 60));
        $this->assertSame(10, $this->storage->increment('b', 0, 60));
    }
}
