<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\Totp\Encoding\Base32;
use Zappzarapp\Security\Totp\Exception\InvalidBase32Exception;
use Zappzarapp\Security\Totp\Exception\InvalidTotpSecretException;
use Zappzarapp\Security\Totp\TotpAlgorithm;
use Zappzarapp\Security\Totp\TotpSecret;

#[CoversClass(TotpSecret::class)]
#[CoversClass(InvalidTotpSecretException::class)]
#[UsesClass(Base32::class)]
#[UsesClass(InvalidBase32Exception::class)]
#[UsesClass(TotpAlgorithm::class)]
#[UsesClass(SecretValue::class)]
final class TotpSecretTest extends TestCase
{
    #[Test]
    public function testHoldsSecretMaterial(): void
    {
        $bytes = random_bytes(20);

        $this->assertSame($bytes, (new TotpSecret($bytes))->bytes());
    }

    #[Test]
    public function testRejectsSecretBelowMinimumLength(): void
    {
        $this->expectException(InvalidTotpSecretException::class);
        $this->expectExceptionMessage('TOTP secret must be at least 20 bytes (160 bit), got 19 bytes');

        new TotpSecret(random_bytes(19));
    }

    #[Test]
    public function testGenerateSizesSecretForSha1(): void
    {
        $this->assertSame(20, strlen(TotpSecret::generate()->bytes()));
    }

    #[Test]
    public function testGenerateSizesSecretForSha256(): void
    {
        $this->assertSame(32, strlen(TotpSecret::generate(TotpAlgorithm::Sha256)->bytes()));
    }

    #[Test]
    public function testGenerateSizesSecretForSha512(): void
    {
        $this->assertSame(64, strlen(TotpSecret::generate(TotpAlgorithm::Sha512)->bytes()));
    }

    #[Test]
    public function testGenerateProducesUniqueSecrets(): void
    {
        $this->assertNotSame(TotpSecret::generate()->bytes(), TotpSecret::generate()->bytes());
    }

    #[Test]
    public function testBase32RoundTrip(): void
    {
        $secret = TotpSecret::generate();

        $this->assertSame(
            $secret->bytes(),
            TotpSecret::fromBase32($secret->toBase32())->bytes()
        );
    }

    #[Test]
    public function testFromBase32RejectsInvalidEncoding(): void
    {
        $this->expectException(InvalidBase32Exception::class);

        TotpSecret::fromBase32('not!valid!base32!!!!!!!!!!!!!!!!');
    }

    #[Test]
    public function testFromBase32RejectsTooShortSecret(): void
    {
        $this->expectException(InvalidTotpSecretException::class);

        TotpSecret::fromBase32(Base32::encode(random_bytes(10)));
    }

    #[Test]
    public function testDebugOutputIsRedacted(): void
    {
        $this->assertSame(
            ['material' => '***REDACTED***'],
            (new TotpSecret(random_bytes(20)))->__debugInfo()
        );
    }
}
