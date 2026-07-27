<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Encryption;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Encryption\Ciphertext;
use Zappzarapp\Security\Encryption\Exception\InvalidCiphertextException;

#[CoversClass(Ciphertext::class)]
#[CoversClass(InvalidCiphertextException::class)]
final class CiphertextTest extends TestCase
{
    #[Test]
    public function testHoldsNonceAndPayload(): void
    {
        $nonce   = random_bytes(24);
        $payload = random_bytes(48);

        $ciphertext = new Ciphertext($nonce, $payload);

        $this->assertSame($nonce, $ciphertext->nonce);
        $this->assertSame($payload, $ciphertext->payload);
    }

    #[DataProvider('invalidNonceLengthProvider')]
    #[Test]
    public function testRejectsInvalidNonceLength(int $length): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage(
            sprintf('Ciphertext payload is truncated (expected at least 24 bytes, got %d bytes)', $length)
        );

        new Ciphertext(str_repeat("\x01", $length), random_bytes(16));
    }

    /**
     * @return array<string, array{int}>
     */
    public static function invalidNonceLengthProvider(): array
    {
        return [
            'empty'         => [0],
            'one too short' => [23],
            'one too long'  => [25],
        ];
    }

    #[Test]
    public function testRejectsPayloadShorterThanTag(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage(
            'Ciphertext payload is truncated (expected at least 16 bytes, got 15 bytes)'
        );

        new Ciphertext(random_bytes(24), str_repeat("\x01", 15));
    }

    #[Test]
    public function testStringRoundTrip(): void
    {
        $ciphertext = new Ciphertext(random_bytes(24), random_bytes(48));

        $restored = Ciphertext::fromString($ciphertext->toString());

        $this->assertSame($ciphertext->nonce, $restored->nonce);
        $this->assertSame($ciphertext->payload, $restored->payload);
    }

    #[Test]
    public function testToStringUsesVersionPrefix(): void
    {
        $nonce   = random_bytes(24);
        $payload = random_bytes(16);

        $encoded = (new Ciphertext($nonce, $payload))->toString();

        $this->assertSame('v1.' . base64_encode($nonce . $payload), $encoded);
    }

    #[DataProvider('unsupportedFormatProvider')]
    #[Test]
    public function testFromStringRejectsUnsupportedFormat(string $encoded): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext format not supported (expected "v1." prefix)');

        Ciphertext::fromString($encoded);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unsupportedFormatProvider(): array
    {
        return [
            'empty string'    => [''],
            'unknown version' => ['v2.QUJD'],
            'missing prefix'  => ['QUJD'],
        ];
    }

    #[DataProvider('invalidBase64Provider')]
    #[Test]
    public function testFromStringRejectsInvalidBase64(string $payload): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext payload is not valid base64');

        Ciphertext::fromString('v1.' . $payload);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidBase64Provider(): array
    {
        return [
            'invalid characters' => ['!!invalid!!'],
            'dollar sign'        => ['QUJD$RUZH'],
        ];
    }

    #[Test]
    public function testFromStringRejectsTruncatedBinary(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage(
            'Ciphertext payload is truncated (expected at least 40 bytes, got 39 bytes)'
        );

        Ciphertext::fromString('v1.' . base64_encode(str_repeat("\x01", 39)));
    }

    #[Test]
    public function testFromStringAcceptsMinimumLength(): void
    {
        $binary = str_repeat("\x01", 40);

        $ciphertext = Ciphertext::fromString('v1.' . base64_encode($binary));

        $this->assertSame(substr($binary, 0, 24), $ciphertext->nonce);
        $this->assertSame(substr($binary, 24), $ciphertext->payload);
    }

    #[Test]
    public function testToBinaryConcatenatesNonceAndPayload(): void
    {
        $nonce   = random_bytes(24);
        $payload = random_bytes(20);

        $this->assertSame($nonce . $payload, (new Ciphertext($nonce, $payload))->toBinary());
    }

    #[Test]
    public function testConstants(): void
    {
        $this->assertSame('v1.', Ciphertext::FORMAT_PREFIX);
        $this->assertSame(24, Ciphertext::NONCE_BYTES);
        $this->assertSame(16, Ciphertext::TAG_BYTES);
    }
}
