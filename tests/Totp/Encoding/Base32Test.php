<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp\Encoding;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Totp\Encoding\Base32;
use Zappzarapp\Security\Totp\Exception\InvalidBase32Exception;

#[CoversClass(Base32::class)]
#[CoversClass(InvalidBase32Exception::class)]
final class Base32Test extends TestCase
{
    /**
     * RFC 4648 section 10 test vectors (unpadded form)
     *
     * @return array<string, array{string, string}>
     */
    public static function rfc4648VectorProvider(): array
    {
        return [
            'empty'  => ['', ''],
            'f'      => ['f', 'MY'],
            'fo'     => ['fo', 'MZXQ'],
            'foo'    => ['foo', 'MZXW6'],
            'foob'   => ['foob', 'MZXW6YQ'],
            'fooba'  => ['fooba', 'MZXW6YTB'],
            'foobar' => ['foobar', 'MZXW6YTBOI'],
        ];
    }

    #[DataProvider('rfc4648VectorProvider')]
    #[Test]
    public function testEncodeMatchesRfc4648Vectors(string $bytes, string $encoded): void
    {
        $this->assertSame($encoded, Base32::encode($bytes));
    }

    #[DataProvider('rfc4648VectorProvider')]
    #[Test]
    public function testDecodeMatchesRfc4648Vectors(string $bytes, string $encoded): void
    {
        $this->assertSame($bytes, Base32::decode($encoded));
    }

    #[Test]
    public function testDecodeAcceptsTrailingPadding(): void
    {
        $this->assertSame('foobar', Base32::decode('MZXW6YTBOI======'));
    }

    #[Test]
    public function testDecodeAcceptsLowercase(): void
    {
        $this->assertSame('foobar', Base32::decode('mzxw6ytboi'));
    }

    #[Test]
    public function testBinaryRoundTrip(): void
    {
        $bytes = random_bytes(20);

        $this->assertSame($bytes, Base32::decode(Base32::encode($bytes)));
    }

    #[Test]
    public function testDecodeRejectsCharacterOutsideAlphabet(): void
    {
        $this->expectException(InvalidBase32Exception::class);
        $this->expectExceptionMessage('Base32 input contains characters outside the RFC 4648 alphabet');

        Base32::decode('MZXW1YTB');
    }

    #[Test]
    public function testDecodeRejectsPaddingInTheMiddle(): void
    {
        $this->expectException(InvalidBase32Exception::class);
        $this->expectExceptionMessage('Base32 input has invalid padding');

        Base32::decode('MZ=W');
    }

    #[Test]
    public function testDecodeRejectsImpossibleLength(): void
    {
        $this->expectException(InvalidBase32Exception::class);
        $this->expectExceptionMessage('Base32 input has invalid padding');

        Base32::decode('M');
    }

    #[Test]
    public function testDecodeAcceptsFullPaddingBlock(): void
    {
        $this->assertSame('f', Base32::decode('MY======'));
    }

    #[Test]
    public function testDecodeRejectsWrongPaddingLength(): void
    {
        $this->expectException(InvalidBase32Exception::class);
        $this->expectExceptionMessage('Base32 input has invalid padding');

        Base32::decode('MY=');
    }

    #[Test]
    public function testDecodeRejectsPaddingAfterCompleteBlock(): void
    {
        $this->expectException(InvalidBase32Exception::class);
        $this->expectExceptionMessage('Base32 input has invalid padding');

        Base32::decode('MZXW6YTB=');
    }

    #[Test]
    public function testDecodeRejectsFullPaddingBlockAfterCompleteBlock(): void
    {
        $this->expectException(InvalidBase32Exception::class);
        $this->expectExceptionMessage('Base32 input has invalid padding');

        Base32::decode('MZXW6YTB========');
    }

    #[Test]
    public function testDecodeRejectsPaddingOnlyInput(): void
    {
        $this->expectException(InvalidBase32Exception::class);
        $this->expectExceptionMessage('Base32 input has invalid padding');

        Base32::decode('====');
    }

    #[Test]
    public function testDecodeRejectsNonCanonicalTrailingBits(): void
    {
        $this->expectException(InvalidBase32Exception::class);
        $this->expectExceptionMessage('Base32 input is not canonical (unused trailing bits must be zero)');

        Base32::decode('MZXW6YTBOJ');
    }

    #[Test]
    public function testAlphabetIsRfc4648(): void
    {
        $this->assertSame('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', Base32::ALPHABET);
    }
}
