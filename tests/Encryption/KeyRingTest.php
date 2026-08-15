<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Encryption;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Encryption\EncryptionKey;
use Zappzarapp\Security\Encryption\Exception\InvalidKeyRingException;
use Zappzarapp\Security\Encryption\Exception\UnknownKeyVersionException;
use Zappzarapp\Security\Encryption\KeyRing;
use Zappzarapp\Security\Encryption\VersionedCiphertext;
use Zappzarapp\Security\Secrets\SecretValue;

#[CoversClass(KeyRing::class)]
#[CoversClass(InvalidKeyRingException::class)]
#[CoversClass(UnknownKeyVersionException::class)]
#[UsesClass(EncryptionKey::class)]
#[UsesClass(SecretValue::class)]
final class KeyRingTest extends TestCase
{
    #[Test]
    public function testCreateStartsAtVersionOne(): void
    {
        $key  = EncryptionKey::generate();
        $ring = KeyRing::create($key);

        $this->assertSame(1, $ring->activeVersion);
        $this->assertSame([1], $ring->versions());
        $this->assertSame(1, $ring->oldestVersion());
        $this->assertSame($key, $ring->activeKey());
        $this->assertSame($key, $ring->key(1));
        $this->assertTrue($ring->has(1));
        $this->assertFalse($ring->has(2));
    }

    #[Test]
    public function testFromKeysAcceptsUnorderedVersions(): void
    {
        $keyTwo  = EncryptionKey::generate();
        $keyFive = EncryptionKey::generate();

        $ring = KeyRing::fromKeys([5 => $keyFive, 2 => $keyTwo], 5);

        $this->assertSame(5, $ring->activeVersion);
        $this->assertSame([2, 5], $ring->versions());
        $this->assertSame(2, $ring->oldestVersion());
        $this->assertSame($keyFive, $ring->activeKey());
        $this->assertSame($keyTwo, $ring->key(2));
    }

    #[Test]
    public function testFromKeysAcceptsMaximumVersion(): void
    {
        $key  = EncryptionKey::generate();
        $ring = KeyRing::fromKeys([VersionedCiphertext::MAX_KEY_VERSION => $key], VersionedCiphertext::MAX_KEY_VERSION);

        $this->assertSame(VersionedCiphertext::MAX_KEY_VERSION, $ring->activeVersion);
    }

    #[Test]
    public function testFromKeysRejectsEmptyRing(): void
    {
        $this->expectException(InvalidKeyRingException::class);
        $this->expectExceptionMessage('Key ring must contain at least one key');

        KeyRing::fromKeys([], 1);
    }

    #[Test]
    public function testFromKeysRejectsVersionZero(): void
    {
        $this->expectException(InvalidKeyRingException::class);
        $this->expectExceptionMessage('Key version must be between 1 and 999999999, got 0');

        KeyRing::fromKeys([0 => EncryptionKey::generate()], 0);
    }

    #[Test]
    public function testFromKeysRejectsNegativeVersion(): void
    {
        $this->expectException(InvalidKeyRingException::class);

        KeyRing::fromKeys([-3 => EncryptionKey::generate()], -3);
    }

    #[Test]
    public function testFromKeysRejectsVersionAboveMaximum(): void
    {
        $version = VersionedCiphertext::MAX_KEY_VERSION + 1;

        $this->expectException(InvalidKeyRingException::class);
        $this->expectExceptionMessage('Key version must be between 1 and 999999999, got 1000000000');

        KeyRing::fromKeys([$version => EncryptionKey::generate()], $version);
    }

    #[Test]
    public function testFromKeysRejectsMissingActiveVersion(): void
    {
        $this->expectException(InvalidKeyRingException::class);
        $this->expectExceptionMessage('Active key version 2 is not present in the key ring');

        KeyRing::fromKeys([1 => EncryptionKey::generate()], 2);
    }

    #[Test]
    public function testWithRotatedKeyActivatesNextVersion(): void
    {
        $oldKey = EncryptionKey::generate();
        $newKey = EncryptionKey::generate();

        $rotated = KeyRing::create($oldKey)->withRotatedKey($newKey);

        $this->assertSame(2, $rotated->activeVersion);
        $this->assertSame([1, 2], $rotated->versions());
        $this->assertSame($newKey, $rotated->activeKey());
        $this->assertSame($oldKey, $rotated->key(1));
    }

    #[Test]
    public function testWithRotatedKeyUsesHighestVersionPlusOne(): void
    {
        $ring = KeyRing::fromKeys([
            1 => EncryptionKey::generate(),
            3 => EncryptionKey::generate(),
        ], 3);

        $rotated = $ring->withRotatedKey(EncryptionKey::generate());

        $this->assertSame(4, $rotated->activeVersion);
        $this->assertSame([1, 3, 4], $rotated->versions());
    }

    #[Test]
    public function testWithRotatedKeyDoesNotModifyOriginal(): void
    {
        $ring = KeyRing::create(EncryptionKey::generate());

        $ring->withRotatedKey(EncryptionKey::generate());

        $this->assertSame(1, $ring->activeVersion);
        $this->assertSame([1], $ring->versions());
    }

    #[Test]
    public function testWithRotatedKeyReachesMaximumVersion(): void
    {
        $key  = EncryptionKey::generate();
        $ring = KeyRing::fromKeys(
            [VersionedCiphertext::MAX_KEY_VERSION - 1 => $key],
            VersionedCiphertext::MAX_KEY_VERSION - 1
        );

        $rotated = $ring->withRotatedKey(EncryptionKey::generate());

        $this->assertSame(VersionedCiphertext::MAX_KEY_VERSION, $rotated->activeVersion);
    }

    #[Test]
    public function testConsecutiveRotationsUseSequentialVersions(): void
    {
        $rotated = KeyRing::create(EncryptionKey::generate())
            ->withRotatedKey(EncryptionKey::generate())
            ->withRotatedKey(EncryptionKey::generate());

        $this->assertSame(3, $rotated->activeVersion);
        $this->assertSame([1, 2, 3], $rotated->versions());
    }

    #[Test]
    public function testWithRotatedKeyDoesNotReuseRetiredVersion(): void
    {
        $ring = KeyRing::fromKeys([
            1 => EncryptionKey::generate(),
            2 => EncryptionKey::generate(),
            3 => EncryptionKey::generate(),
        ], 1);

        $rotated = $ring->withoutKey(3)->withRotatedKey(EncryptionKey::generate());

        $this->assertSame(4, $rotated->activeVersion);
        $this->assertSame([1, 2, 4], $rotated->versions());
        $this->assertFalse($rotated->has(3));
    }

    #[Test]
    public function testWithRotatedKeyRejectsVersionOverflow(): void
    {
        $key  = EncryptionKey::generate();
        $ring = KeyRing::fromKeys([VersionedCiphertext::MAX_KEY_VERSION => $key], VersionedCiphertext::MAX_KEY_VERSION);

        $this->expectException(InvalidKeyRingException::class);
        $this->expectExceptionMessage('Key version must be between 1 and 999999999, got 1000000000');

        $ring->withRotatedKey(EncryptionKey::generate());
    }

    #[Test]
    public function testWithoutKeyRetiresVersion(): void
    {
        $ring = KeyRing::fromKeys([
            1 => EncryptionKey::generate(),
            2 => EncryptionKey::generate(),
            3 => EncryptionKey::generate(),
        ], 3);

        $retired = $ring->withoutKey(2);

        $this->assertSame([1, 3], $retired->versions());
        $this->assertFalse($retired->has(2));
        $this->assertSame(3, $retired->activeVersion);
        $this->assertSame(1, $retired->oldestVersion());
    }

    #[Test]
    public function testWithoutKeyKeepsKeysAfterRemovedVersion(): void
    {
        $first = EncryptionKey::generate();
        $third = EncryptionKey::generate();
        $ring  = KeyRing::fromKeys([
            1 => $first,
            2 => EncryptionKey::generate(),
            3 => $third,
        ], 1);

        $retired = $ring->withoutKey(2);

        $this->assertSame([1, 3], $retired->versions());
        $this->assertSame($first, $retired->key(1));
        $this->assertSame($third, $retired->key(3));
        $this->assertSame(1, $retired->activeVersion);
    }

    #[Test]
    public function testWithoutKeyDoesNotModifyOriginal(): void
    {
        $ring = KeyRing::fromKeys([
            1 => EncryptionKey::generate(),
            2 => EncryptionKey::generate(),
        ], 2);

        $ring->withoutKey(1);

        $this->assertTrue($ring->has(1));
    }

    #[Test]
    public function testWithoutKeyRejectsActiveVersion(): void
    {
        $ring = KeyRing::fromKeys([
            1 => EncryptionKey::generate(),
            2 => EncryptionKey::generate(),
        ], 2);

        $this->expectException(InvalidKeyRingException::class);
        $this->expectExceptionMessage('Cannot remove key version 2 while it is the active encryption key');

        $ring->withoutKey(2);
    }

    #[Test]
    public function testWithoutKeyRejectsUnknownVersion(): void
    {
        $ring = KeyRing::create(EncryptionKey::generate());

        $this->expectException(UnknownKeyVersionException::class);
        $this->expectExceptionMessage('Key version 7 is not present in the key ring (removed or never provisioned)');

        $ring->withoutKey(7);
    }

    #[Test]
    public function testKeyRejectsUnknownVersion(): void
    {
        $ring = KeyRing::create(EncryptionKey::generate());

        $this->expectException(UnknownKeyVersionException::class);
        $this->expectExceptionMessage('Key version 9 is not present in the key ring (removed or never provisioned)');

        $ring->key(9);
    }

    #[Test]
    public function testKeyAfterRetirementThrows(): void
    {
        $ring = KeyRing::fromKeys([
            1 => EncryptionKey::generate(),
            2 => EncryptionKey::generate(),
        ], 2)->withoutKey(1);

        $this->expectException(UnknownKeyVersionException::class);

        $ring->key(1);
    }
}
