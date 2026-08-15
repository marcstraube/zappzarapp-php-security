<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\Totp\Exception\InvalidTotpConfigException;
use Zappzarapp\Security\Totp\Hotp\HotpGenerator;
use Zappzarapp\Security\Totp\TotpAlgorithm;
use Zappzarapp\Security\Totp\TotpAuthenticator;
use Zappzarapp\Security\Totp\TotpConfig;
use Zappzarapp\Security\Totp\TotpSecret;
use Zappzarapp\Security\Totp\TotpVerificationResult;

#[CoversClass(TotpAuthenticator::class)]
#[CoversClass(InvalidTotpConfigException::class)]
#[UsesClass(HotpGenerator::class)]
#[UsesClass(TotpAlgorithm::class)]
#[UsesClass(TotpConfig::class)]
#[UsesClass(TotpSecret::class)]
#[UsesClass(TotpVerificationResult::class)]
#[UsesClass(SecretValue::class)]
final class TotpAuthenticatorTest extends TestCase
{
    private const string SHA1_SECRET = '12345678901234567890';

    private TotpSecret $secret;

    private TotpAuthenticator $totp;

    protected function setUp(): void
    {
        $this->secret = new TotpSecret(self::SHA1_SECRET);
        $this->totp   = new TotpAuthenticator();
    }

    /**
     * RFC 6238 Appendix B test vectors (8 digits, 30s period)
     *
     * @return array<string, array{TotpAlgorithm, string, int, string}>
     */
    public static function rfc6238VectorProvider(): array
    {
        $sha1Secret   = '12345678901234567890';
        $sha256Secret = '12345678901234567890123456789012';
        $sha512Secret = '1234567890123456789012345678901234567890123456789012345678901234';

        return [
            'sha1 t=59'            => [TotpAlgorithm::Sha1, $sha1Secret, 59, '94287082'],
            'sha1 t=1111111109'    => [TotpAlgorithm::Sha1, $sha1Secret, 1111111109, '07081804'],
            'sha1 t=1111111111'    => [TotpAlgorithm::Sha1, $sha1Secret, 1111111111, '14050471'],
            'sha1 t=1234567890'    => [TotpAlgorithm::Sha1, $sha1Secret, 1234567890, '89005924'],
            'sha1 t=2000000000'    => [TotpAlgorithm::Sha1, $sha1Secret, 2000000000, '69279037'],
            'sha1 t=20000000000'   => [TotpAlgorithm::Sha1, $sha1Secret, 20000000000, '65353130'],
            'sha256 t=59'          => [TotpAlgorithm::Sha256, $sha256Secret, 59, '46119246'],
            'sha256 t=1111111109'  => [TotpAlgorithm::Sha256, $sha256Secret, 1111111109, '68084774'],
            'sha256 t=1111111111'  => [TotpAlgorithm::Sha256, $sha256Secret, 1111111111, '67062674'],
            'sha256 t=1234567890'  => [TotpAlgorithm::Sha256, $sha256Secret, 1234567890, '91819424'],
            'sha256 t=2000000000'  => [TotpAlgorithm::Sha256, $sha256Secret, 2000000000, '90698825'],
            'sha256 t=20000000000' => [TotpAlgorithm::Sha256, $sha256Secret, 20000000000, '77737706'],
            'sha512 t=59'          => [TotpAlgorithm::Sha512, $sha512Secret, 59, '90693936'],
            'sha512 t=1111111109'  => [TotpAlgorithm::Sha512, $sha512Secret, 1111111109, '25091201'],
            'sha512 t=1111111111'  => [TotpAlgorithm::Sha512, $sha512Secret, 1111111111, '99943326'],
            'sha512 t=1234567890'  => [TotpAlgorithm::Sha512, $sha512Secret, 1234567890, '93441116'],
            'sha512 t=2000000000'  => [TotpAlgorithm::Sha512, $sha512Secret, 2000000000, '38618901'],
            'sha512 t=20000000000' => [TotpAlgorithm::Sha512, $sha512Secret, 20000000000, '47863826'],
        ];
    }

    #[DataProvider('rfc6238VectorProvider')]
    #[Test]
    public function testGenerateCodeMatchesRfc6238Vectors(
        TotpAlgorithm $algorithm,
        string $secretBytes,
        int $timestamp,
        string $expected,
    ): void {
        $totp = new TotpAuthenticator(new TotpConfig(digits: 8, algorithm: $algorithm));

        $this->assertSame($expected, $totp->generateCode(new TotpSecret($secretBytes), $timestamp));
    }

    #[Test]
    public function testVerifyAcceptsCurrentCode(): void
    {
        $timestamp = 1111111111;
        $code      = $this->totp->generateCode($this->secret, $timestamp);

        $result = $this->totp->verify($this->secret, $code, timestamp: $timestamp);

        $this->assertTrue($result->valid);
        $this->assertSame(intdiv($timestamp, 30), $result->matchedTimeStep);
    }

    #[Test]
    public function testVerifyAcceptsPreviousStepWithinWindow(): void
    {
        $timestamp = 1111111111;
        $code      = $this->totp->generateCode($this->secret, $timestamp - 30);

        $result = $this->totp->verify($this->secret, $code, timestamp: $timestamp);

        $this->assertTrue($result->valid);
        $this->assertSame(intdiv($timestamp, 30) - 1, $result->matchedTimeStep);
    }

    #[Test]
    public function testVerifyAcceptsNextStepWithinWindow(): void
    {
        $timestamp = 1111111111;
        $code      = $this->totp->generateCode($this->secret, $timestamp + 30);

        $result = $this->totp->verify($this->secret, $code, timestamp: $timestamp);

        $this->assertTrue($result->valid);
        $this->assertSame(intdiv($timestamp, 30) + 1, $result->matchedTimeStep);
    }

    #[Test]
    public function testVerifyRejectsCodeOutsideWindow(): void
    {
        $timestamp = 1111111111;
        $code      = $this->totp->generateCode($this->secret, $timestamp - 60);

        $result = $this->totp->verify($this->secret, $code, timestamp: $timestamp);

        $this->assertFalse($result->valid);
        $this->assertNull($result->matchedTimeStep);
    }

    #[Test]
    public function testVerifyWithZeroWindowRejectsAdjacentSteps(): void
    {
        $totp      = new TotpAuthenticator(new TotpConfig(window: 0));
        $timestamp = 1111111111;

        $previous = $totp->generateCode($this->secret, $timestamp - 30);
        $current  = $totp->generateCode($this->secret, $timestamp);

        $this->assertFalse($totp->verify($this->secret, $previous, timestamp: $timestamp)->valid);
        $this->assertTrue($totp->verify($this->secret, $current, timestamp: $timestamp)->valid);
    }

    #[Test]
    public function testVerifyRejectsReplayedCode(): void
    {
        $timestamp = 1111111111;
        $code      = $this->totp->generateCode($this->secret, $timestamp);

        $first = $this->totp->verify($this->secret, $code, timestamp: $timestamp);

        $replayed = $this->totp->verify(
            $this->secret,
            $code,
            lastAcceptedTimeStep: $first->matchedTimeStep,
            timestamp: $timestamp
        );

        $this->assertFalse($replayed->valid);
    }

    #[Test]
    public function testVerifyRejectsOlderStepAfterAcceptance(): void
    {
        $timestamp = 1111111111;
        $previous  = $this->totp->generateCode($this->secret, $timestamp - 30);

        $result = $this->totp->verify(
            $this->secret,
            $previous,
            lastAcceptedTimeStep: intdiv($timestamp, 30),
            timestamp: $timestamp
        );

        $this->assertFalse($result->valid);
    }

    #[Test]
    public function testVerifyAcceptsNewerStepAfterAcceptance(): void
    {
        $timestamp = 1111111111;
        $next      = $this->totp->generateCode($this->secret, $timestamp + 30);

        $result = $this->totp->verify(
            $this->secret,
            $next,
            lastAcceptedTimeStep: intdiv($timestamp, 30),
            timestamp: $timestamp
        );

        $this->assertTrue($result->valid);
    }

    #[Test]
    public function testVerifyRejectsWrongCode(): void
    {
        $this->assertFalse(
            $this->totp->verify($this->secret, '000000', timestamp: 1111111111)->valid
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedCodeProvider(): array
    {
        return [
            'empty'          => [''],
            'too short'      => ['12345'],
            'too long'       => ['1234567'],
            'letters'        => ['12a456'],
            'signed'         => ['+12345'],
            'whitespace'     => ['123 45'],
        ];
    }

    #[DataProvider('malformedCodeProvider')]
    #[Test]
    public function testVerifyRejectsMalformedCode(string $code): void
    {
        $result = $this->totp->verify($this->secret, $code, timestamp: 1111111111);

        $this->assertFalse($result->valid);
    }

    #[DataProvider('malformedCodeProvider')]
    #[Test]
    public function testVerifyChecksCodeFormatBeforeAnythingElse(string $code): void
    {
        $result = $this->totp->verify($this->secret, $code, timestamp: -1);

        $this->assertFalse($result->valid);
    }

    #[Test]
    public function testVerifySkipsNegativeStepsNearEpoch(): void
    {
        $code = $this->totp->generateCode($this->secret, 0);

        $result = $this->totp->verify($this->secret, $code, timestamp: 0);

        $this->assertTrue($result->valid);
        $this->assertSame(0, $result->matchedTimeStep);
    }

    #[Test]
    public function testGenerateCodeRejectsNegativeTimestamp(): void
    {
        $this->expectException(InvalidTotpConfigException::class);
        $this->expectExceptionMessage('Timestamp must not be negative, got -1');

        $this->totp->generateCode($this->secret, -1);
    }

    #[Test]
    public function testVerifyRejectsNegativeTimestamp(): void
    {
        $this->expectException(InvalidTotpConfigException::class);

        $this->totp->verify($this->secret, '123456', timestamp: -5);
    }

    #[Test]
    public function testUsesInjectedClock(): void
    {
        $clock = new class implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable('@1111111111');
            }
        };

        $totp = new TotpAuthenticator(clock: $clock);

        $this->assertSame(
            $totp->generateCode($this->secret, 1111111111),
            $totp->generateCode($this->secret)
        );
        $this->assertTrue(
            $totp->verify($this->secret, $totp->generateCode($this->secret))->valid
        );
    }

    #[Test]
    public function testFallsBackToSystemTime(): void
    {
        $code = $this->totp->generateCode($this->secret);

        $this->assertTrue($this->totp->verify($this->secret, $code)->valid);
    }

    #[Test]
    public function testRespectsConfiguredPeriod(): void
    {
        $totp      = new TotpAuthenticator(new TotpConfig(period: 60));
        $timestamp = 1111111111;
        $code      = $totp->generateCode($this->secret, $timestamp);

        $result = $totp->verify($this->secret, $code, timestamp: $timestamp);

        $this->assertTrue($result->valid);
        $this->assertSame(intdiv($timestamp, 60), $result->matchedTimeStep);
    }
}
