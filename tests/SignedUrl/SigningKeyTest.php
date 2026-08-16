<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\SignedUrl;

use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\SignedUrl\Exception\InvalidSigningKeyException;
use Zappzarapp\Security\SignedUrl\SigningKey;

#[CoversClass(SigningKey::class)]
#[CoversClass(InvalidSigningKeyException::class)]
#[UsesClass(SecretValue::class)]
final class SigningKeyTest extends TestCase
{
    #[Test]
    public function testGenerateProducesKeyOfMinimumLength(): void
    {
        $key = SigningKey::generate();

        $this->assertSame(32, strlen($key->bytes()));
    }

    #[Test]
    public function testGenerateProducesUniqueKeys(): void
    {
        $first  = SigningKey::generate();
        $second = SigningKey::generate();

        $this->assertNotSame($first->bytes(), $second->bytes());
    }

    #[Test]
    public function testAcceptsExactly32Bytes(): void
    {
        $bytes = random_bytes(32);

        $key = new SigningKey($bytes);

        $this->assertSame($bytes, $key->bytes());
    }

    #[Test]
    public function testAcceptsLongerKeys(): void
    {
        $bytes = random_bytes(64);

        $key = new SigningKey($bytes);

        $this->assertSame($bytes, $key->bytes());
    }

    #[DataProvider('tooShortProvider')]
    #[Test]
    public function testRejectsTooShortKeys(int $length): void
    {
        $this->expectException(InvalidSigningKeyException::class);
        $this->expectExceptionMessage(
            sprintf('Signing key must be at least 32 bytes, got %d bytes', $length)
        );

        new SigningKey(str_repeat("\x42", $length));
    }

    /**
     * @return array<string, array{int}>
     */
    public static function tooShortProvider(): array
    {
        return [
            'empty'         => [0],
            'one byte'      => [1],
            'one too short' => [31],
        ];
    }

    #[Test]
    public function testBase64RoundTrip(): void
    {
        $key = SigningKey::generate();

        $restored = SigningKey::fromBase64($key->toBase64());

        $this->assertSame($key->bytes(), $restored->bytes());
    }

    #[DataProvider('invalidBase64Provider')]
    #[Test]
    public function testFromBase64RejectsInvalidEncoding(string $encoded): void
    {
        $this->expectException(InvalidSigningKeyException::class);
        $this->expectExceptionMessage('Signing key material is not valid base64');

        SigningKey::fromBase64($encoded);
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
    public function testFromBase64RejectsTooShortDecodedKey(): void
    {
        $this->expectException(InvalidSigningKeyException::class);
        $this->expectExceptionMessage('Signing key must be at least 32 bytes, got 3 bytes');

        SigningKey::fromBase64(base64_encode('abc'));
    }

    #[Test]
    public function testFromSecretValue(): void
    {
        $bytes  = random_bytes(32);
        $secret = new SecretValue(base64_encode($bytes));

        $key = SigningKey::fromSecretValue($secret);

        $this->assertSame($bytes, $key->bytes());
    }

    #[Test]
    public function testMinLengthConstant(): void
    {
        $this->assertSame(32, SigningKey::MIN_LENGTH_BYTES);
    }

    #[Test]
    public function testDebugInfoRedactsMaterial(): void
    {
        $key = SigningKey::generate();

        $this->assertSame(['material' => '***REDACTED***'], $key->__debugInfo());
    }

    #[Test]
    public function testJsonEncodeDoesNotLeakMaterial(): void
    {
        $key = SigningKey::generate();

        $this->assertSame('{}', json_encode($key));
    }

    #[Test]
    public function testSerializeThrows(): void
    {
        $key = SigningKey::generate();

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('SecretValue must not be serialized');

        serialize($key);
    }
}
