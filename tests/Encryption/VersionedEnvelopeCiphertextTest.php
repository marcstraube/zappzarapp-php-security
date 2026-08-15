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
use Zappzarapp\Security\Encryption\Exception\InvalidCiphertextException;
use Zappzarapp\Security\Encryption\VersionedCiphertext;
use Zappzarapp\Security\Encryption\VersionedEnvelopeCiphertext;

#[CoversClass(VersionedEnvelopeCiphertext::class)]
#[CoversClass(InvalidCiphertextException::class)]
#[UsesClass(Ciphertext::class)]
#[UsesClass(VersionedCiphertext::class)]
#[UsesClass(EnvelopeCiphertext::class)]
final class VersionedEnvelopeCiphertextTest extends TestCase
{
    #[Test]
    public function testExposesKeyVersionAndParts(): void
    {
        $wrappedKey = $this->makeWrappedKey(3);
        $payload    = $this->makePayload();

        $envelope = new VersionedEnvelopeCiphertext($wrappedKey, $payload);

        $this->assertSame(3, $envelope->keyVersion());
        $this->assertSame($wrappedKey, $envelope->wrappedKey);
        $this->assertSame($payload, $envelope->payload);
    }

    #[Test]
    public function testRejectsWrappedKeyWithUnexpectedSize(): void
    {
        $tooShort = new VersionedCiphertext(1, new Ciphertext(
            random_bytes(Ciphertext::NONCE_BYTES),
            random_bytes(EncryptionKey::LENGTH_BYTES + Ciphertext::TAG_BYTES - 1)
        ));

        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext payload is truncated (expected at least 48 bytes, got 47 bytes)');

        new VersionedEnvelopeCiphertext($tooShort, $this->makePayload());
    }

    #[Test]
    public function testToStringUsesVersionedPrefix(): void
    {
        $envelope = new VersionedEnvelopeCiphertext($this->makeWrappedKey(17), $this->makePayload());

        $this->assertStringStartsWith('e2.17.', $envelope->toString());
    }

    #[Test]
    public function testStringRoundTrip(): void
    {
        $wrappedKey = $this->makeWrappedKey(5);
        $payload    = $this->makePayload();
        $envelope   = new VersionedEnvelopeCiphertext($wrappedKey, $payload);

        $parsed = VersionedEnvelopeCiphertext::fromString($envelope->toString());

        $this->assertSame(5, $parsed->keyVersion());
        $this->assertSame($wrappedKey->ciphertext->toBinary(), $parsed->wrappedKey->ciphertext->toBinary());
        $this->assertSame($payload->toBinary(), $parsed->payload->toBinary());
    }

    #[Test]
    public function testFromStringRejectsMissingPrefix(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext format not supported (expected "e2." prefix)');

        VersionedEnvelopeCiphertext::fromString('e1.' . base64_encode(random_bytes(128)));
    }

    #[Test]
    public function testFromStringRejectsInvalidVersion(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage(
            'Ciphertext key version must be a positive integer with at most 9 digits'
        );

        VersionedEnvelopeCiphertext::fromString('e2.0.' . base64_encode(random_bytes(128)));
    }

    #[Test]
    public function testFromStringRejectsInvalidBase64(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext payload is not valid base64');

        VersionedEnvelopeCiphertext::fromString('e2.1.$$$not-base64$$$');
    }

    #[Test]
    public function testFromStringRejectsTruncatedBinary(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext payload is truncated (expected at least 112 bytes, got 111 bytes)');

        VersionedEnvelopeCiphertext::fromString('e2.1.' . base64_encode(random_bytes(111)));
    }

    private function makeWrappedKey(int $version): VersionedCiphertext
    {
        return new VersionedCiphertext($version, new Ciphertext(
            random_bytes(Ciphertext::NONCE_BYTES),
            random_bytes(EncryptionKey::LENGTH_BYTES + Ciphertext::TAG_BYTES)
        ));
    }

    private function makePayload(): Ciphertext
    {
        return new Ciphertext(
            random_bytes(Ciphertext::NONCE_BYTES),
            random_bytes(Ciphertext::TAG_BYTES + 32)
        );
    }
}
