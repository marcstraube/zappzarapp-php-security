<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp\Hotp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\Totp\Exception\InvalidTotpConfigException;
use Zappzarapp\Security\Totp\Hotp\HotpGenerator;
use Zappzarapp\Security\Totp\TotpAlgorithm;
use Zappzarapp\Security\Totp\TotpSecret;

#[CoversClass(HotpGenerator::class)]
#[CoversClass(InvalidTotpConfigException::class)]
#[UsesClass(TotpSecret::class)]
#[UsesClass(TotpAlgorithm::class)]
#[UsesClass(SecretValue::class)]
final class HotpGeneratorTest extends TestCase
{
    private const string RFC4226_SECRET = '12345678901234567890';

    private HotpGenerator $generator;

    protected function setUp(): void
    {
        $this->generator = new HotpGenerator();
    }

    /**
     * RFC 4226 Appendix D test vectors
     *
     * @return array<string, array{int, string}>
     */
    public static function rfc4226VectorProvider(): array
    {
        return [
            'counter 0' => [0, '755224'],
            'counter 1' => [1, '287082'],
            'counter 2' => [2, '359152'],
            'counter 3' => [3, '969429'],
            'counter 4' => [4, '338314'],
            'counter 5' => [5, '254676'],
            'counter 6' => [6, '287922'],
            'counter 7' => [7, '162583'],
            'counter 8' => [8, '399871'],
            'counter 9' => [9, '520489'],
        ];
    }

    #[DataProvider('rfc4226VectorProvider')]
    #[Test]
    public function testMatchesRfc4226Vectors(int $counter, string $expected): void
    {
        $secret = new TotpSecret(self::RFC4226_SECRET);

        $this->assertSame($expected, $this->generator->generate($secret, $counter));
    }

    #[Test]
    public function testPadsLeadingZeros(): void
    {
        $secret = new TotpSecret(self::RFC4226_SECRET);

        $code = $this->generator->generate($secret, 21, 8);

        $this->assertSame(8, strlen($code));
    }

    #[Test]
    public function testEightDigitCodeExtendsSixDigitCode(): void
    {
        $secret = new TotpSecret(self::RFC4226_SECRET);

        $this->assertSame('755224', $this->generator->generate($secret, 0));
        $this->assertSame('84755224', $this->generator->generate($secret, 0, 8));
    }

    #[Test]
    public function testAlgorithmsProduceDistinctCodes(): void
    {
        $secret = new TotpSecret(self::RFC4226_SECRET);

        $sha1   = $this->generator->generate($secret, 0);
        $sha256 = $this->generator->generate($secret, 0, 6, TotpAlgorithm::Sha256);
        $sha512 = $this->generator->generate($secret, 0, 6, TotpAlgorithm::Sha512);

        $this->assertNotSame($sha1, $sha256);
        $this->assertNotSame($sha1, $sha512);
        $this->assertNotSame($sha256, $sha512);
    }

    #[Test]
    public function testRejectsNegativeCounter(): void
    {
        $this->expectException(InvalidTotpConfigException::class);
        $this->expectExceptionMessage('HOTP counter must not be negative, got -1');

        $this->generator->generate(new TotpSecret(self::RFC4226_SECRET), -1);
    }

    #[Test]
    public function testRejectsTooFewDigits(): void
    {
        $this->expectException(InvalidTotpConfigException::class);
        $this->expectExceptionMessage('TOTP digits must be between 6 and 8, got 5');

        $this->generator->generate(new TotpSecret(self::RFC4226_SECRET), 0, 5);
    }

    #[Test]
    public function testRejectsTooManyDigits(): void
    {
        $this->expectException(InvalidTotpConfigException::class);
        $this->expectExceptionMessage('TOTP digits must be between 6 and 8, got 9');

        $this->generator->generate(new TotpSecret(self::RFC4226_SECRET), 0, 9);
    }
}
