<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Encryption;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Encryption\Ciphertext;
use Zappzarapp\Security\Encryption\EncryptionKey;
use Zappzarapp\Security\Encryption\Exception\DecryptionException;
use Zappzarapp\Security\Encryption\Exception\UnknownKeyVersionException;
use Zappzarapp\Security\Encryption\KeyRing;
use Zappzarapp\Security\Encryption\KeyRingEncryptor;
use Zappzarapp\Security\Encryption\SymmetricEncryptor;
use Zappzarapp\Security\Encryption\VersionedCiphertext;
use Zappzarapp\Security\Secrets\SecretValue;

#[CoversClass(KeyRingEncryptor::class)]
#[UsesClass(Ciphertext::class)]
#[UsesClass(EncryptionKey::class)]
#[UsesClass(KeyRing::class)]
#[UsesClass(SymmetricEncryptor::class)]
#[UsesClass(VersionedCiphertext::class)]
#[UsesClass(DecryptionException::class)]
#[UsesClass(UnknownKeyVersionException::class)]
#[UsesClass(SecretValue::class)]
final class KeyRingEncryptorTest extends TestCase
{
    private EncryptionKey $oldKey;

    private EncryptionKey $activeKey;

    private KeyRingEncryptor $encryptor;

    protected function setUp(): void
    {
        $this->oldKey    = EncryptionKey::generate();
        $this->activeKey = EncryptionKey::generate();
        $this->encryptor = new KeyRingEncryptor(KeyRing::fromKeys([
            1 => $this->oldKey,
            2 => $this->activeKey,
        ], 2));
    }

    #[Test]
    public function testRoundTrip(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example');

        $this->assertSame('plaintext-example', $this->encryptor->decrypt($ciphertext));
    }

    #[Test]
    public function testRoundTripWithAdditionalData(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example', 'user:42');

        $this->assertSame(
            'plaintext-example',
            $this->encryptor->decrypt($ciphertext, 'user:42')
        );
    }

    #[Test]
    public function testEncryptStampsActiveVersion(): void
    {
        $this->assertSame(2, $this->encryptor->encrypt('plaintext-example')->keyVersion);
    }

    #[Test]
    public function testDecryptSelectsKeyByVersion(): void
    {
        $oldRingEncryptor = new KeyRingEncryptor(KeyRing::create($this->oldKey));

        $ciphertext = $oldRingEncryptor->encrypt('plaintext-example', 'user:42');

        $this->assertSame(1, $ciphertext->keyVersion);
        $this->assertSame(
            'plaintext-example',
            $this->encryptor->decrypt($ciphertext, 'user:42')
        );
    }

    #[Test]
    public function testDecryptRejectsMismatchedAdditionalData(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example', 'user:42');

        $this->expectException(DecryptionException::class);

        $this->encryptor->decrypt($ciphertext, 'user:43');
    }

    #[Test]
    public function testDecryptRejectsUnknownKeyVersion(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example');
        $restamped  = new VersionedCiphertext(3, $ciphertext->ciphertext);

        $this->expectException(UnknownKeyVersionException::class);
        $this->expectExceptionMessage('Key version 3 is not present in the key ring (removed or never provisioned)');

        $this->encryptor->decrypt($restamped);
    }

    #[Test]
    public function testDecryptRejectsRestampedVersionEvenWithIdenticalKeys(): void
    {
        $key       = EncryptionKey::generate();
        $encryptor = new KeyRingEncryptor(KeyRing::fromKeys([1 => $key, 2 => $key], 2));

        $restamped = new VersionedCiphertext(1, $encryptor->encrypt('plaintext-example')->ciphertext);

        $this->expectException(DecryptionException::class);

        $encryptor->decrypt($restamped);
    }

    #[Test]
    public function testAdditionalDataBindingContract(): void
    {
        $inner = (new SymmetricEncryptor())->encrypt(
            'plaintext-example',
            $this->oldKey,
            pack('N', 1) . 'user:42'
        );

        $this->assertSame(
            'plaintext-example',
            $this->encryptor->decrypt(new VersionedCiphertext(1, $inner), 'user:42')
        );
    }

    #[Test]
    public function testNeedsRotationForOutdatedVersion(): void
    {
        $oldRingEncryptor = new KeyRingEncryptor(KeyRing::create($this->oldKey));

        $this->assertTrue(
            $this->encryptor->needsRotation($oldRingEncryptor->encrypt('plaintext-example'))
        );
    }

    #[Test]
    public function testNeedsRotationIsFalseForActiveVersion(): void
    {
        $this->assertFalse(
            $this->encryptor->needsRotation($this->encryptor->encrypt('plaintext-example'))
        );
    }

    #[Test]
    public function testRotateReencryptsUnderActiveKey(): void
    {
        $oldRingEncryptor = new KeyRingEncryptor(KeyRing::create($this->oldKey));
        $outdated         = $oldRingEncryptor->encrypt('plaintext-example', 'user:42');

        $rotated = $this->encryptor->rotate($outdated, 'user:42');

        $this->assertSame(2, $rotated->keyVersion);
        $this->assertFalse($this->encryptor->needsRotation($rotated));
        $this->assertSame('plaintext-example', $this->encryptor->decrypt($rotated, 'user:42'));
    }

    #[Test]
    public function testRotateReturnsCurrentCiphertextUnchanged(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example');

        $this->assertSame($ciphertext, $this->encryptor->rotate($ciphertext));
    }

    #[Test]
    public function testRotateRejectsUnknownKeyVersion(): void
    {
        $restamped = new VersionedCiphertext(
            9,
            $this->encryptor->encrypt('plaintext-example')->ciphertext
        );

        $this->expectException(UnknownKeyVersionException::class);

        $this->encryptor->rotate($restamped);
    }

    #[Test]
    public function testDecryptLegacyUsesOldestKey(): void
    {
        $legacy = (new SymmetricEncryptor())->encrypt('plaintext-example', $this->oldKey);

        $this->assertSame('plaintext-example', $this->encryptor->decryptLegacy($legacy));
    }

    #[Test]
    public function testDecryptLegacyWithAdditionalData(): void
    {
        $legacy = (new SymmetricEncryptor())->encrypt('plaintext-example', $this->oldKey, 'user:42');

        $this->assertSame(
            'plaintext-example',
            $this->encryptor->decryptLegacy($legacy, 'user:42')
        );
    }

    #[Test]
    public function testDecryptLegacyRejectsCiphertextUnderActiveKey(): void
    {
        $legacy = (new SymmetricEncryptor())->encrypt('plaintext-example', $this->activeKey);

        $this->expectException(DecryptionException::class);

        $this->encryptor->decryptLegacy($legacy);
    }

    #[Test]
    public function testRotateLegacyProducesActiveVersion(): void
    {
        $legacy = (new SymmetricEncryptor())->encrypt('plaintext-example', $this->oldKey, 'user:42');

        $rotated = $this->encryptor->rotateLegacy($legacy, 'user:42');

        $this->assertSame(2, $rotated->keyVersion);
        $this->assertSame('plaintext-example', $this->encryptor->decrypt($rotated, 'user:42'));
    }
}
