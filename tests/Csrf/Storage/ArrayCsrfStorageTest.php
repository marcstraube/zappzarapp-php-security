<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Storage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\Storage\ArrayCsrfStorage;
use Zappzarapp\Security\Csrf\Storage\CsrfStorageInterface;

#[CoversClass(ArrayCsrfStorage::class)]
final class ArrayCsrfStorageTest extends TestCase
{
    private ArrayCsrfStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new ArrayCsrfStorage();
    }

    #[Test]
    public function testImplementsCsrfStorageInterface(): void
    {
        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(CsrfStorageInterface::class, $this->storage);
    }

    #[Test]
    public function testStoreAndRetrieve(): void
    {
        $this->storage->store('key1', 'token1');

        $this->assertSame('token1', $this->storage->retrieve('key1'));
    }

    #[Test]
    public function testRetrieveReturnsNullForMissingKey(): void
    {
        $this->assertNull($this->storage->retrieve('nonexistent'));
    }

    #[Test]
    public function testHasReturnsTrue(): void
    {
        $this->storage->store('key1', 'token1');

        $this->assertTrue($this->storage->has('key1'));
    }

    #[Test]
    public function testHasReturnsFalse(): void
    {
        $this->assertFalse($this->storage->has('nonexistent'));
    }

    #[Test]
    public function testRemove(): void
    {
        $this->storage->store('key1', 'token1');
        $this->storage->remove('key1');

        $this->assertNull($this->storage->retrieve('key1'));
        $this->assertFalse($this->storage->has('key1'));
    }

    #[Test]
    public function testRemoveNonexistentKey(): void
    {
        $this->storage->remove('nonexistent');

        $this->assertFalse($this->storage->has('nonexistent'));
    }

    #[Test]
    public function testClear(): void
    {
        $this->storage->store('key1', 'token1');
        $this->storage->store('key2', 'token2');

        $this->storage->clear();

        $this->assertNull($this->storage->retrieve('key1'));
        $this->assertNull($this->storage->retrieve('key2'));
    }

    #[Test]
    public function testMultipleKeys(): void
    {
        $this->storage->store('key1', 'token1');
        $this->storage->store('key2', 'token2');
        $this->storage->store('key3', 'token3');

        $this->assertSame('token1', $this->storage->retrieve('key1'));
        $this->assertSame('token2', $this->storage->retrieve('key2'));
        $this->assertSame('token3', $this->storage->retrieve('key3'));
    }

    #[Test]
    public function testOverwriteExistingKey(): void
    {
        $this->storage->store('key1', 'token1');
        $this->storage->store('key1', 'token2');

        $this->assertSame('token2', $this->storage->retrieve('key1'));
    }

    #[Test]
    public function testStoreWithTtlIgnoresTtl(): void
    {
        $this->storage->store('key1', 'token1', 1);

        $this->assertSame('token1', $this->storage->retrieve('key1'));
    }

    // --- Count Method ---

    #[Test]
    public function testCountReturnsZeroWhenEmpty(): void
    {
        $this->assertSame(0, $this->storage->count());
    }

    #[Test]
    public function testCountReturnsCorrectNumber(): void
    {
        $this->storage->store('key1', 'token1');
        $this->storage->store('key2', 'token2');
        $this->storage->store('key3', 'token3');

        $this->assertSame(3, $this->storage->count());
    }

    #[Test]
    public function testCountDecreasesAfterRemove(): void
    {
        $this->storage->store('key1', 'token1');
        $this->storage->store('key2', 'token2');

        $this->storage->remove('key1');

        $this->assertSame(1, $this->storage->count());
    }

    #[Test]
    public function testCountReturnsZeroAfterClear(): void
    {
        $this->storage->store('key1', 'token1');
        $this->storage->store('key2', 'token2');

        $this->storage->clear();

        $this->assertSame(0, $this->storage->count());
    }

    #[Test]
    public function testCountDoesNotChangeOnOverwrite(): void
    {
        $this->storage->store('key1', 'token1');
        $this->storage->store('key1', 'token2');

        $this->assertSame(1, $this->storage->count());
    }

    // --- Token Expiration ---

    #[Test]
    public function testTokenExpiresAfterTtl(): void
    {
        $this->storage->store('key1', 'token1', 1);

        $this->assertSame('token1', $this->storage->retrieve('key1'));

        sleep(2);

        $this->assertNull($this->storage->retrieve('key1'));
    }

    #[Test]
    public function testExpiredTokenIsRemovedFromCount(): void
    {
        $this->storage->store('key1', 'token1', 1);
        /** @noinspection PhpRedundantOptionalArgumentInspection Test explicitly verifies null TTL behavior */
        $this->storage->store('key2', 'token2', null);

        $this->assertSame(2, $this->storage->count());

        sleep(2);

        // Retrieve triggers cleanup of expired token
        $this->storage->retrieve('key1');

        $this->assertSame(1, $this->storage->count());
    }

    #[Test]
    public function testHasReturnsFalseForExpiredToken(): void
    {
        $this->storage->store('key1', 'token1', 1);

        sleep(2);

        $this->assertFalse($this->storage->has('key1'));
    }
}
