<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Encryption;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Encryption\Ciphertext;
use Zappzarapp\Security\Encryption\Exception\InvalidCiphertextException;
use Zappzarapp\Security\Encryption\VersionedCiphertext;

#[CoversClass(VersionedCiphertext::class)]
#[CoversClass(InvalidCiphertextException::class)]
#[UsesClass(Ciphertext::class)]
final class VersionedCiphertextTest extends TestCase
{
    #[Test]
    public function testExposesVersionAndCiphertext(): void
    {
        $inner = $this->makeCiphertext();

        $versioned = new VersionedCiphertext(7, $inner);

        $this->assertSame(7, $versioned->keyVersion);
        $this->assertSame($inner, $versioned->ciphertext);
    }

    #[Test]
    public function testAcceptsVersionOne(): void
    {
        $this->assertSame(1, (new VersionedCiphertext(1, $this->makeCiphertext()))->keyVersion);
    }

    #[Test]
    public function testAcceptsMaximumVersion(): void
    {
        $versioned = new VersionedCiphertext(
            VersionedCiphertext::MAX_KEY_VERSION,
            $this->makeCiphertext()
        );

        $this->assertSame(999_999_999, $versioned->keyVersion);
    }

    #[Test]
    public function testRejectsVersionZero(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage(
            'Ciphertext key version must be a positive integer with at most 9 digits'
        );

        new VersionedCiphertext(0, $this->makeCiphertext());
    }

    #[Test]
    public function testRejectsNegativeVersion(): void
    {
        $this->expectException(InvalidCiphertextException::class);

        new VersionedCiphertext(-1, $this->makeCiphertext());
    }

    #[Test]
    public function testRejectsVersionAboveMaximum(): void
    {
        $this->expectException(InvalidCiphertextException::class);

        new VersionedCiphertext(VersionedCiphertext::MAX_KEY_VERSION + 1, $this->makeCiphertext());
    }

    #[Test]
    public function testToStringUsesVersionedPrefix(): void
    {
        $versioned = new VersionedCiphertext(42, $this->makeCiphertext());

        $this->assertStringStartsWith('v2.42.', $versioned->toString());
    }

    #[Test]
    public function testStringRoundTrip(): void
    {
        $inner     = $this->makeCiphertext();
        $versioned = new VersionedCiphertext(123456789, $inner);

        $parsed = VersionedCiphertext::fromString($versioned->toString());

        $this->assertSame(123456789, $parsed->keyVersion);
        $this->assertSame($inner->nonce, $parsed->ciphertext->nonce);
        $this->assertSame($inner->payload, $parsed->ciphertext->payload);
    }

    #[Test]
    public function testFromStringRejectsMissingPrefix(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext format not supported (expected "v2." prefix)');

        VersionedCiphertext::fromString('v1.' . base64_encode(random_bytes(64)));
    }

    #[Test]
    public function testFromStringRejectsMissingVersionSeparator(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage(
            'Ciphertext key version must be a positive integer with at most 9 digits'
        );

        VersionedCiphertext::fromString('v2.123');
    }

    #[Test]
    public function testFromStringRejectsEmptyVersion(): void
    {
        $this->expectException(InvalidCiphertextException::class);

        VersionedCiphertext::fromString('v2..' . base64_encode(random_bytes(64)));
    }

    #[Test]
    public function testFromStringRejectsVersionZero(): void
    {
        $this->expectException(InvalidCiphertextException::class);

        VersionedCiphertext::fromString('v2.0.' . base64_encode(random_bytes(64)));
    }

    #[Test]
    public function testFromStringRejectsLeadingZero(): void
    {
        $this->expectException(InvalidCiphertextException::class);

        VersionedCiphertext::fromString('v2.01.' . base64_encode(random_bytes(64)));
    }

    #[Test]
    public function testFromStringRejectsNonNumericVersion(): void
    {
        $this->expectException(InvalidCiphertextException::class);

        VersionedCiphertext::fromString('v2.1a.' . base64_encode(random_bytes(64)));
    }

    #[Test]
    public function testFromStringRejectsTenDigitVersion(): void
    {
        $this->expectException(InvalidCiphertextException::class);

        VersionedCiphertext::fromString('v2.1000000000.' . base64_encode(random_bytes(64)));
    }

    #[Test]
    public function testFromStringRejectsInvalidBase64(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext payload is not valid base64');

        VersionedCiphertext::fromString('v2.1.$$$not-base64$$$');
    }

    #[Test]
    public function testFromStringRejectsTruncatedBinary(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext payload is truncated (expected at least 40 bytes, got 39 bytes)');

        VersionedCiphertext::fromString('v2.1.' . base64_encode(random_bytes(39)));
    }

    private function makeCiphertext(): Ciphertext
    {
        return new Ciphertext(
            random_bytes(Ciphertext::NONCE_BYTES),
            random_bytes(Ciphertext::TAG_BYTES + 16)
        );
    }
}
