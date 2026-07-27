<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Encryption;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Encryption\Ciphertext;
use Zappzarapp\Security\Encryption\EnvelopeCiphertext;
use Zappzarapp\Security\Encryption\Exception\InvalidCiphertextException;

#[CoversClass(EnvelopeCiphertext::class)]
#[CoversClass(InvalidCiphertextException::class)]
#[UsesClass(Ciphertext::class)]
final class EnvelopeCiphertextTest extends TestCase
{
    #[Test]
    public function testHoldsWrappedKeyAndPayload(): void
    {
        $wrappedKey = new Ciphertext(random_bytes(24), random_bytes(48));
        $payload    = new Ciphertext(random_bytes(24), random_bytes(64));

        $envelope = new EnvelopeCiphertext($wrappedKey, $payload);

        $this->assertSame($wrappedKey, $envelope->wrappedKey);
        $this->assertSame($payload, $envelope->payload);
    }

    #[DataProvider('invalidWrappedKeyLengthProvider')]
    #[Test]
    public function testRejectsWrappedKeyOfWrongSize(int $payloadBytes): void
    {
        $wrappedKey = new Ciphertext(random_bytes(24), str_repeat("\x02", $payloadBytes));

        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage(
            sprintf('Ciphertext payload is truncated (expected at least 48 bytes, got %d bytes)', $payloadBytes)
        );

        new EnvelopeCiphertext($wrappedKey, new Ciphertext(random_bytes(24), random_bytes(32)));
    }

    /**
     * @return array<string, array{int}>
     */
    public static function invalidWrappedKeyLengthProvider(): array
    {
        return [
            'tag only'      => [16],
            'one too short' => [47],
            'one too long'  => [49],
        ];
    }

    #[Test]
    public function testStringRoundTrip(): void
    {
        $envelope = new EnvelopeCiphertext(
            new Ciphertext(random_bytes(24), random_bytes(48)),
            new Ciphertext(random_bytes(24), random_bytes(80))
        );

        $restored = EnvelopeCiphertext::fromString($envelope->toString());

        $this->assertSame($envelope->wrappedKey->nonce, $restored->wrappedKey->nonce);
        $this->assertSame($envelope->wrappedKey->payload, $restored->wrappedKey->payload);
        $this->assertSame($envelope->payload->nonce, $restored->payload->nonce);
        $this->assertSame($envelope->payload->payload, $restored->payload->payload);
    }

    #[Test]
    public function testToStringUsesVersionPrefix(): void
    {
        $wrappedKey = new Ciphertext(random_bytes(24), random_bytes(48));
        $payload    = new Ciphertext(random_bytes(24), random_bytes(32));

        $encoded = (new EnvelopeCiphertext($wrappedKey, $payload))->toString();

        $this->assertSame(
            'e1.' . base64_encode($wrappedKey->toBinary() . $payload->toBinary()),
            $encoded
        );
    }

    #[DataProvider('unsupportedFormatProvider')]
    #[Test]
    public function testFromStringRejectsUnsupportedFormat(string $encoded): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext format not supported (expected "e1." prefix)');

        EnvelopeCiphertext::fromString($encoded);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unsupportedFormatProvider(): array
    {
        return [
            'empty string'      => [''],
            'symmetric prefix'  => ['v1.QUJD'],
            'unknown version'   => ['e2.QUJD'],
        ];
    }

    #[Test]
    public function testFromStringRejectsInvalidBase64(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage('Ciphertext payload is not valid base64');

        EnvelopeCiphertext::fromString('e1.!!invalid!!');
    }

    #[Test]
    public function testFromStringRejectsTruncatedBinary(): void
    {
        $this->expectException(InvalidCiphertextException::class);
        $this->expectExceptionMessage(
            'Ciphertext payload is truncated (expected at least 112 bytes, got 111 bytes)'
        );

        EnvelopeCiphertext::fromString('e1.' . base64_encode(str_repeat("\x01", 111)));
    }

    #[Test]
    public function testFromStringAcceptsMinimumLength(): void
    {
        $binary = str_repeat("\x01", 112);

        $envelope = EnvelopeCiphertext::fromString('e1.' . base64_encode($binary));

        $this->assertSame(substr($binary, 0, 24), $envelope->wrappedKey->nonce);
        $this->assertSame(substr($binary, 24, 48), $envelope->wrappedKey->payload);
        $this->assertSame(substr($binary, 72, 24), $envelope->payload->nonce);
        $this->assertSame(substr($binary, 96), $envelope->payload->payload);
    }

    #[Test]
    public function testConstants(): void
    {
        $this->assertSame('e1.', EnvelopeCiphertext::FORMAT_PREFIX);
        $this->assertSame(72, EnvelopeCiphertext::WRAPPED_KEY_BYTES);
    }
}
