<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Encryption;

use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Encryption\EncryptionKey;
use Zappzarapp\Security\Encryption\Exception\InvalidKeyException;
use Zappzarapp\Security\Secrets\SecretValue;

#[CoversClass(EncryptionKey::class)]
#[CoversClass(InvalidKeyException::class)]
#[UsesClass(SecretValue::class)]
final class EncryptionKeyTest extends TestCase
{
    #[Test]
    public function testGenerateProducesKeyOfCorrectLength(): void
    {
        $key = EncryptionKey::generate();

        $this->assertSame(32, strlen($key->bytes()));
    }

    #[Test]
    public function testGenerateProducesUniqueKeys(): void
    {
        $first  = EncryptionKey::generate();
        $second = EncryptionKey::generate();

        $this->assertNotSame($first->bytes(), $second->bytes());
    }

    #[Test]
    public function testAcceptsExactly32Bytes(): void
    {
        $bytes = random_bytes(32);

        $key = new EncryptionKey($bytes);

        $this->assertSame($bytes, $key->bytes());
    }

    #[DataProvider('invalidLengthProvider')]
    #[Test]
    public function testRejectsWrongLength(int $length): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage(
            sprintf('Encryption key must be exactly 32 bytes, got %d bytes', $length)
        );

        new EncryptionKey(str_repeat("\x42", $length));
    }

    /**
     * @return array<string, array{int}>
     */
    public static function invalidLengthProvider(): array
    {
        return [
            'empty'         => [0],
            'one byte'      => [1],
            'one too short' => [31],
            'one too long'  => [33],
            'double length' => [64],
        ];
    }

    #[Test]
    public function testBase64RoundTrip(): void
    {
        $key = EncryptionKey::generate();

        $restored = EncryptionKey::fromBase64($key->toBase64());

        $this->assertSame($key->bytes(), $restored->bytes());
    }

    #[DataProvider('invalidBase64Provider')]
    #[Test]
    public function testFromBase64RejectsInvalidEncoding(string $encoded): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Encryption key material is not valid base64');

        EncryptionKey::fromBase64($encoded);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidBase64Provider(): array
    {
        return [
            'invalid characters' => ['!!not-base64!!'],
            'dollar sign'        => ['QUJD$RUZH'],
        ];
    }

    #[Test]
    public function testFromBase64RejectsWrongDecodedLength(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Encryption key must be exactly 32 bytes, got 3 bytes');

        EncryptionKey::fromBase64(base64_encode('abc'));
    }

    #[Test]
    public function testFromSecretValue(): void
    {
        $bytes  = random_bytes(32);
        $secret = new SecretValue(base64_encode($bytes));

        $key = EncryptionKey::fromSecretValue($secret);

        $this->assertSame($bytes, $key->bytes());
    }

    #[Test]
    public function testLengthConstant(): void
    {
        $this->assertSame(32, EncryptionKey::LENGTH_BYTES);
    }

    #[Test]
    public function testDebugInfoRedactsMaterial(): void
    {
        $key = EncryptionKey::generate();

        $this->assertSame(['material' => '***REDACTED***'], $key->__debugInfo());
    }

    #[Test]
    public function testJsonEncodeDoesNotLeakMaterial(): void
    {
        $key = EncryptionKey::generate();

        $this->assertSame('{}', json_encode($key));
    }

    #[Test]
    public function testSerializeThrows(): void
    {
        $key = EncryptionKey::generate();

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('SecretValue must not be serialized');

        serialize($key);
    }
}
