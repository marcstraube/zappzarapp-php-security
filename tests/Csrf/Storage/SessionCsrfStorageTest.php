<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Storage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Csrf\Storage\CsrfStorageInterface;
use Zappzarapp\Security\Csrf\Storage\SessionCsrfStorage;

#[CoversClass(SessionCsrfStorage::class)]
final class SessionCsrfStorageTest extends TestCase
{
    private SessionCsrfStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new SessionCsrfStorage();
    }

    protected function tearDown(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_unset();
            session_destroy();
        }

        // Reset session ID for next test
        session_id('');
    }

    private function startTestSession(): void
    {
        // Generate unique session ID per test to avoid conflicts
        // Session IDs only allow A-Z, a-z, 0-9, "-", ","
        session_id('test' . bin2hex(random_bytes(8)));
        session_start();
    }

    public function testImplementsCsrfStorageInterface(): void
    {
        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(CsrfStorageInterface::class, $this->storage);
    }

    // --- Session Not Started Errors ---

    public function testStoreThrowsWhenSessionNotStarted(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Session must be started');

        $this->storage->store('key', 'token');
    }

    public function testRetrieveThrowsWhenSessionNotStarted(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Session must be started');

        $this->storage->retrieve('key');
    }

    public function testRemoveThrowsWhenSessionNotStarted(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Session must be started');

        $this->storage->remove('key');
    }

    public function testHasThrowsWhenSessionNotStarted(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Session must be started');

        $this->storage->has('key');
    }

    public function testClearThrowsWhenSessionNotStarted(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Session must be started');

        $this->storage->clear();
    }

    // --- With Active Session ---

    public function testStoreAndRetrieve(): void
    {
        $this->startTestSession();

        $this->storage->store('key1', 'token1');

        $this->assertSame('token1', $this->storage->retrieve('key1'));
    }

    public function testRetrieveReturnsNullForMissingKey(): void
    {
        $this->startTestSession();

        $this->assertNull($this->storage->retrieve('nonexistent'));
    }

    public function testHasReturnsTrue(): void
    {
        $this->startTestSession();

        $this->storage->store('key1', 'token1');

        $this->assertTrue($this->storage->has('key1'));
    }

    public function testHasReturnsFalse(): void
    {
        $this->startTestSession();

        $this->assertFalse($this->storage->has('nonexistent'));
    }

    public function testRemove(): void
    {
        $this->startTestSession();

        $this->storage->store('key1', 'token1');
        $this->storage->remove('key1');

        $this->assertNull($this->storage->retrieve('key1'));
        $this->assertFalse($this->storage->has('key1'));
    }

    public function testRemoveNonexistentKey(): void
    {
        $this->startTestSession();

        $this->storage->remove('nonexistent');

        $this->assertFalse($this->storage->has('nonexistent'));
    }

    public function testClear(): void
    {
        $this->startTestSession();

        $this->storage->store('key1', 'token1');
        $this->storage->store('key2', 'token2');

        $this->storage->clear();

        $this->assertNull($this->storage->retrieve('key1'));
        $this->assertNull($this->storage->retrieve('key2'));
    }

    public function testMultipleKeys(): void
    {
        $this->startTestSession();

        $this->storage->store('key1', 'token1');
        $this->storage->store('key2', 'token2');
        $this->storage->store('key3', 'token3');

        $this->assertSame('token1', $this->storage->retrieve('key1'));
        $this->assertSame('token2', $this->storage->retrieve('key2'));
        $this->assertSame('token3', $this->storage->retrieve('key3'));
    }

    public function testOverwriteExistingKey(): void
    {
        $this->startTestSession();

        $this->storage->store('key1', 'token1');
        $this->storage->store('key1', 'token2');

        $this->assertSame('token2', $this->storage->retrieve('key1'));
    }

    public function testCustomSessionKey(): void
    {
        $this->startTestSession();

        $storage = new SessionCsrfStorage('custom_csrf_key');
        $storage->store('key1', 'token1');

        $this->assertArrayHasKey('custom_csrf_key', $_SESSION);
        $this->assertSame('token1', $storage->retrieve('key1'));
    }

    // --- Token Expiration ---

    public function testTokenExpiresAfterTtl(): void
    {
        $this->startTestSession();

        // Store with 1 second TTL
        $this->storage->store('key1', 'token1', 1);

        // Should be retrievable immediately
        $this->assertSame('token1', $this->storage->retrieve('key1'));

        // Wait for expiration
        sleep(2);

        // Should return null after expiration
        $this->assertNull($this->storage->retrieve('key1'));
    }

    public function testTokenDoesNotExpireWithNullTtl(): void
    {
        $this->startTestSession();

        /** @noinspection PhpRedundantOptionalArgumentInspection Test explicitly verifies null TTL behavior */
        $this->storage->store('key1', 'token1', null);

        // Should be retrievable
        $this->assertSame('token1', $this->storage->retrieve('key1'));
    }

    public function testExpiredTokenIsRemovedFromStorage(): void
    {
        $this->startTestSession();

        $this->storage->store('key1', 'token1', 1);

        sleep(2);

        // Retrieve triggers cleanup
        $this->storage->retrieve('key1');

        // Check that it's actually removed from session
        $this->assertFalse($this->storage->has('key1'));
    }

    public function testHasReturnsFalseForExpiredToken(): void
    {
        $this->startTestSession();

        $this->storage->store('key1', 'token1', 1);

        sleep(2);

        $this->assertFalse($this->storage->has('key1'));
    }
}
