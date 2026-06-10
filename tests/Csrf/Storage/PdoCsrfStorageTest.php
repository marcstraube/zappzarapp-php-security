<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Storage;

use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\Exception\CsrfStorageException;
use Zappzarapp\Security\Csrf\Storage\PdoCsrfStorage;

#[CoversClass(PdoCsrfStorage::class)]
#[RequiresPhpExtension('pdo_sqlite')]
final class PdoCsrfStorageTest extends TestCase
{
    private PDO $pdo;

    private PdoCsrfStorage $storage;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:', null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);

        $this->pdo->exec(sprintf(PdoCsrfStorage::SCHEMA['sqlite'], 'csrf_tokens', 'csrf_tokens', 'csrf_tokens'));

        $this->storage = new PdoCsrfStorage($this->pdo);
    }

    #[Test]
    public function testRetrieveReturnsNullForMissingKey(): void
    {
        $this->assertNull($this->storage->retrieve('nonexistent'));
    }

    #[Test]
    public function testStoreAndRetrieve(): void
    {
        $this->storage->store('session1', 'token-value', 3600);

        $this->assertSame('token-value', $this->storage->retrieve('session1'));
    }

    #[Test]
    public function testStoreWithoutTtlNeverExpires(): void
    {
        $this->storage->store('session1', 'token-value');

        $this->assertSame('token-value', $this->storage->retrieve('session1'));
        $this->assertSame(0, $this->storage->cleanup());
        $this->assertSame('token-value', $this->storage->retrieve('session1'));
    }

    #[Test]
    public function testStoreWithElapsedTtlExpiresImmediately(): void
    {
        // A negative TTL produces a past expiry, exercising store()'s expiry
        // binding without waiting for real time to pass.
        $this->storage->store('session1', 'token-value', -1);

        $this->assertNull($this->storage->retrieve('session1'));
    }

    #[Test]
    public function testStoreOverwritesExistingToken(): void
    {
        $this->storage->store('session1', 'token-one', 3600);
        $this->storage->store('session1', 'token-two', 3600);

        $this->assertSame('token-two', $this->storage->retrieve('session1'));
    }

    #[Test]
    public function testRetrieveReturnsNullForExpiredToken(): void
    {
        $this->insertRawToken('csrf:expired', 'old-token', time() - 1);

        $this->assertNull($this->storage->retrieve('expired'));
    }

    #[Test]
    public function testExpiredTokenIsDeletedOnRetrieve(): void
    {
        $this->insertRawToken('csrf:expired', 'old-token', time() - 1);

        $this->storage->retrieve('expired');

        $this->assertSame(0, $this->countRows());
    }

    #[Test]
    public function testTokenAtExpiryBoundaryIsExpired(): void
    {
        $this->insertRawToken('csrf:boundary', 'token', time());

        $this->assertNull($this->storage->retrieve('boundary'));
    }

    #[Test]
    public function testRemoveDeletesToken(): void
    {
        $this->storage->store('session1', 'token-value', 3600);
        $this->storage->remove('session1');

        $this->assertNull($this->storage->retrieve('session1'));
    }

    #[Test]
    public function testHasReturnsTrueForStoredToken(): void
    {
        $this->storage->store('session1', 'token-value', 3600);

        $this->assertTrue($this->storage->has('session1'));
    }

    #[Test]
    public function testHasReturnsFalseForMissingToken(): void
    {
        $this->assertFalse($this->storage->has('session1'));
    }

    #[Test]
    public function testClearRemovesAllPrefixedTokens(): void
    {
        $this->storage->store('session1', 'token-one', 3600);
        $this->storage->store('session2', 'token-two', 3600);

        $this->storage->clear();

        $this->assertNull($this->storage->retrieve('session1'));
        $this->assertNull($this->storage->retrieve('session2'));
        $this->assertSame(0, $this->countRows());
    }

    #[Test]
    public function testClearOnlyRemovesOwnPrefix(): void
    {
        $this->storage->store('session1', 'token-one', 3600);
        $this->insertRawToken('other:session2', 'token-two', time() + 3600);

        $this->storage->clear();

        $this->assertSame(1, $this->countRows());
    }

    #[Test]
    public function testCleanupRemovesExpiredKeepsValid(): void
    {
        $this->insertRawToken('csrf:expired1', 'token', time() - 1);
        $this->insertRawToken('csrf:expired2', 'token', time() - 1);
        $this->storage->store('valid', 'token-value', 3600);

        $deleted = $this->storage->cleanup();

        $this->assertSame(2, $deleted);
        $this->assertSame('token-value', $this->storage->retrieve('valid'));
    }

    #[Test]
    public function testUsesCustomTableName(): void
    {
        $this->pdo->exec(sprintf(PdoCsrfStorage::SCHEMA['sqlite'], 'custom_tokens', 'custom_tokens', 'custom_tokens'));

        $storage = new PdoCsrfStorage($this->pdo, 'custom_tokens');
        $storage->store('session1', 'token-value', 3600);

        $this->assertSame('token-value', $storage->retrieve('session1'));
    }

    #[Test]
    public function testReadFailureThrowsStorageException(): void
    {
        $this->pdo->exec('DROP TABLE csrf_tokens');

        $this->expectException(CsrfStorageException::class);

        $this->storage->retrieve('session1');
    }

    #[Test]
    public function testWriteFailureThrowsStorageException(): void
    {
        $this->pdo->exec('DROP TABLE csrf_tokens');

        $this->expectException(CsrfStorageException::class);

        $this->storage->store('session1', 'token-value', 3600);
    }

    private function insertRawToken(string $prefixedKey, string $token, int $expiresAt): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO csrf_tokens ("key", "token", "expires_at") VALUES (?, ?, ?)',
        );
        $stmt->execute([$prefixedKey, $token, $expiresAt]);
    }

    private function countRows(): int
    {
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM csrf_tokens');
        $stmt->execute();

        return (int) $stmt->fetchColumn();
    }
}
