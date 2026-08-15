<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Encryption;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Encryption\Ciphertext;
use Zappzarapp\Security\Encryption\EncryptionKey;
use Zappzarapp\Security\Encryption\EnvelopeCiphertext;
use Zappzarapp\Security\Encryption\EnvelopeEncryptor;
use Zappzarapp\Security\Encryption\Exception\DecryptionException;
use Zappzarapp\Security\Encryption\Exception\UnknownKeyVersionException;
use Zappzarapp\Security\Encryption\KeyRing;
use Zappzarapp\Security\Encryption\KeyRingEncryptor;
use Zappzarapp\Security\Encryption\KeyRingEnvelopeEncryptor;
use Zappzarapp\Security\Encryption\SymmetricEncryptor;
use Zappzarapp\Security\Encryption\VersionedCiphertext;
use Zappzarapp\Security\Encryption\VersionedEnvelopeCiphertext;
use Zappzarapp\Security\Secrets\SecretValue;

#[CoversClass(KeyRingEnvelopeEncryptor::class)]
#[UsesClass(Ciphertext::class)]
#[UsesClass(EncryptionKey::class)]
#[UsesClass(EnvelopeCiphertext::class)]
#[UsesClass(EnvelopeEncryptor::class)]
#[UsesClass(KeyRing::class)]
#[UsesClass(KeyRingEncryptor::class)]
#[UsesClass(SymmetricEncryptor::class)]
#[UsesClass(VersionedCiphertext::class)]
#[UsesClass(VersionedEnvelopeCiphertext::class)]
#[UsesClass(DecryptionException::class)]
#[UsesClass(UnknownKeyVersionException::class)]
#[UsesClass(SecretValue::class)]
final class KeyRingEnvelopeEncryptorTest extends TestCase
{
    private EncryptionKey $oldKey;

    private EncryptionKey $activeKey;

    private KeyRing $ring;

    private KeyRingEnvelopeEncryptor $envelope;

    protected function setUp(): void
    {
        $this->oldKey    = EncryptionKey::generate();
        $this->activeKey = EncryptionKey::generate();
        $this->ring      = KeyRing::fromKeys([
            1 => $this->oldKey,
            2 => $this->activeKey,
        ], 2);
        $this->envelope  = new KeyRingEnvelopeEncryptor($this->ring);
    }

    #[Test]
    public function testSealOpenRoundTrip(): void
    {
        $sealed = $this->envelope->seal('document-content');

        $this->assertSame('document-content', $this->envelope->open($sealed));
    }

    #[Test]
    public function testSealOpenRoundTripWithAdditionalData(): void
    {
        $sealed = $this->envelope->seal('document-content', 'doc:17');

        $this->assertSame('document-content', $this->envelope->open($sealed, 'doc:17'));
    }

    #[Test]
    public function testSealStampsActiveVersion(): void
    {
        $this->assertSame(2, $this->envelope->seal('document-content')->keyVersion());
    }

    #[Test]
    public function testSealUsesFreshDataKeys(): void
    {
        $first  = $this->envelope->seal('document-content');
        $second = $this->envelope->seal('document-content');

        $this->assertNotSame($first->payload->toBinary(), $second->payload->toBinary());
        $this->assertNotSame(
            $first->wrappedKey->ciphertext->toBinary(),
            $second->wrappedKey->ciphertext->toBinary()
        );
    }

    #[Test]
    public function testStringRoundTrip(): void
    {
        $stored = $this->envelope->seal('document-content', 'doc:17')->toString();

        $this->assertSame(
            'document-content',
            $this->envelope->open(VersionedEnvelopeCiphertext::fromString($stored), 'doc:17')
        );
    }

    #[Test]
    public function testOpenRejectsMismatchedAdditionalData(): void
    {
        $sealed = $this->envelope->seal('document-content', 'doc:17');

        $this->expectException(DecryptionException::class);

        $this->envelope->open($sealed, 'doc:18');
    }

    #[Test]
    public function testOpenRejectsUnknownKeyVersion(): void
    {
        $sealed    = $this->envelope->seal('document-content');
        $restamped = new VersionedEnvelopeCiphertext(
            new VersionedCiphertext(3, $sealed->wrappedKey->ciphertext),
            $sealed->payload
        );

        $this->expectException(UnknownKeyVersionException::class);

        $this->envelope->open($restamped);
    }

    #[Test]
    public function testOpenRejectsRestampedVersionEvenWithIdenticalKeys(): void
    {
        $key      = EncryptionKey::generate();
        $envelope = new KeyRingEnvelopeEncryptor(KeyRing::fromKeys([1 => $key, 2 => $key], 2));

        $sealed    = $envelope->seal('document-content');
        $restamped = new VersionedEnvelopeCiphertext(
            new VersionedCiphertext(1, $sealed->wrappedKey->ciphertext),
            $sealed->payload
        );

        $this->expectException(DecryptionException::class);

        $envelope->open($restamped);
    }

    #[Test]
    public function testWrappedKeyIsNotDecryptableAsGeneralData(): void
    {
        $sealed = $this->envelope->seal('document-content', 'doc:17');

        $this->expectException(DecryptionException::class);

        (new KeyRingEncryptor($this->ring))->decrypt($sealed->wrappedKey, 'doc:17');
    }

    #[Test]
    public function testGeneralCiphertextIsNotUsableAsWrappedKey(): void
    {
        $sealed     = $this->envelope->seal('document-content', 'doc:17');
        $ciphertext = (new KeyRingEncryptor($this->ring))->encrypt(random_bytes(32), 'doc:17');
        $forged     = new VersionedEnvelopeCiphertext($ciphertext, $sealed->payload);

        $this->expectException(DecryptionException::class);

        $this->envelope->open($forged, 'doc:17');
    }

    #[Test]
    public function testWrapContextContract(): void
    {
        $symmetric = new SymmetricEncryptor();
        $dataKey   = EncryptionKey::generate();

        $payload = $symmetric->encrypt('document-content', $dataKey, 'doc:17');
        $wrapped = $symmetric->encrypt(
            $dataKey->bytes(),
            $this->activeKey,
            pack('N', 2) . "zzp:dek-wrap\0" . 'doc:17'
        );

        $envelope = new VersionedEnvelopeCiphertext(new VersionedCiphertext(2, $wrapped), $payload);

        $this->assertSame('document-content', $this->envelope->open($envelope, 'doc:17'));
    }

    #[Test]
    public function testNeedsRotationForOutdatedVersion(): void
    {
        $oldEnvelope = new KeyRingEnvelopeEncryptor(KeyRing::create($this->oldKey));

        $this->assertTrue(
            $this->envelope->needsRotation($oldEnvelope->seal('document-content'))
        );
    }

    #[Test]
    public function testNeedsRotationIsFalseForActiveVersion(): void
    {
        $this->assertFalse(
            $this->envelope->needsRotation($this->envelope->seal('document-content'))
        );
    }

    #[Test]
    public function testRewrapKeepsPayloadUntouched(): void
    {
        $oldEnvelope = new KeyRingEnvelopeEncryptor(KeyRing::create($this->oldKey));
        $outdated    = $oldEnvelope->seal('document-content', 'doc:17');

        $rewrapped = $this->envelope->rewrap($outdated, 'doc:17');

        $this->assertSame(2, $rewrapped->keyVersion());
        $this->assertSame($outdated->payload->toBinary(), $rewrapped->payload->toBinary());
        $this->assertFalse($this->envelope->needsRotation($rewrapped));
        $this->assertSame('document-content', $this->envelope->open($rewrapped, 'doc:17'));
    }

    #[Test]
    public function testRewrapReturnsCurrentEnvelopeUnchanged(): void
    {
        $sealed = $this->envelope->seal('document-content');

        $this->assertSame($sealed, $this->envelope->rewrap($sealed));
    }

    #[Test]
    public function testRewrapRejectsUnknownKeyVersion(): void
    {
        $sealed    = $this->envelope->seal('document-content');
        $restamped = new VersionedEnvelopeCiphertext(
            new VersionedCiphertext(9, $sealed->wrappedKey->ciphertext),
            $sealed->payload
        );

        $this->expectException(UnknownKeyVersionException::class);

        $this->envelope->rewrap($restamped);
    }

    #[Test]
    public function testOpenLegacyUsesOldestKey(): void
    {
        $legacy = (new EnvelopeEncryptor())->seal('document-content', $this->oldKey, 'doc:17');

        $this->assertSame('document-content', $this->envelope->openLegacy($legacy, 'doc:17'));
    }

    #[Test]
    public function testOpenLegacyRejectsEnvelopeUnderActiveKey(): void
    {
        $legacy = (new EnvelopeEncryptor())->seal('document-content', $this->activeKey);

        $this->expectException(DecryptionException::class);

        $this->envelope->openLegacy($legacy);
    }

    #[Test]
    public function testRewrapLegacyKeepsPayloadUntouched(): void
    {
        $legacy = (new EnvelopeEncryptor())->seal('document-content', $this->oldKey, 'doc:17');

        $rewrapped = $this->envelope->rewrapLegacy($legacy, 'doc:17');

        $this->assertSame(2, $rewrapped->keyVersion());
        $this->assertSame($legacy->payload->toBinary(), $rewrapped->payload->toBinary());
        $this->assertSame('document-content', $this->envelope->open($rewrapped, 'doc:17'));
    }
}
