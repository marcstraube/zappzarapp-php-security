<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Totp\Exception\InvalidTotpConfigException;
use Zappzarapp\Security\Totp\TotpAlgorithm;
use Zappzarapp\Security\Totp\TotpConfig;

#[CoversClass(TotpConfig::class)]
#[CoversClass(InvalidTotpConfigException::class)]
#[UsesClass(TotpAlgorithm::class)]
final class TotpConfigTest extends TestCase
{
    #[Test]
    public function testSecureDefaults(): void
    {
        $config = new TotpConfig();

        $this->assertSame(30, $config->period);
        $this->assertSame(6, $config->digits);
        $this->assertSame(TotpAlgorithm::Sha1, $config->algorithm);
        $this->assertSame(1, $config->window);
    }

    #[Test]
    public function testAcceptsBoundaryValues(): void
    {
        $minimum = new TotpConfig(period: 15, digits: 6, window: 0);
        $maximum = new TotpConfig(period: 300, digits: 8, window: 10);

        $this->assertSame(15, $minimum->period);
        $this->assertSame(6, $minimum->digits);
        $this->assertSame(0, $minimum->window);
        $this->assertSame(300, $maximum->period);
        $this->assertSame(8, $maximum->digits);
        $this->assertSame(10, $maximum->window);
    }

    /**
     * @return array<string, array{int, string}>
     */
    public static function invalidPeriodProvider(): array
    {
        return [
            'too short' => [14, 'TOTP period must be between 15 and 300 seconds, got 14'],
            'too long'  => [301, 'TOTP period must be between 15 and 300 seconds, got 301'],
        ];
    }

    #[DataProvider('invalidPeriodProvider')]
    #[Test]
    public function testRejectsInvalidPeriod(int $period, string $message): void
    {
        $this->expectException(InvalidTotpConfigException::class);
        $this->expectExceptionMessage($message);

        new TotpConfig(period: $period);
    }

    /**
     * @return array<string, array{int, string}>
     */
    public static function invalidDigitsProvider(): array
    {
        return [
            'too few'  => [5, 'TOTP digits must be between 6 and 8, got 5'],
            'too many' => [9, 'TOTP digits must be between 6 and 8, got 9'],
        ];
    }

    #[DataProvider('invalidDigitsProvider')]
    #[Test]
    public function testRejectsInvalidDigits(int $digits, string $message): void
    {
        $this->expectException(InvalidTotpConfigException::class);
        $this->expectExceptionMessage($message);

        new TotpConfig(digits: $digits);
    }

    /**
     * @return array<string, array{int, string}>
     */
    public static function invalidWindowProvider(): array
    {
        return [
            'negative'  => [-1, 'TOTP verification window must be between 0 and 10 steps, got -1'],
            'too large' => [11, 'TOTP verification window must be between 0 and 10 steps, got 11'],
        ];
    }

    #[DataProvider('invalidWindowProvider')]
    #[Test]
    public function testRejectsInvalidWindow(int $window, string $message): void
    {
        $this->expectException(InvalidTotpConfigException::class);
        $this->expectExceptionMessage($message);

        new TotpConfig(window: $window);
    }

    #[Test]
    public function testWithPeriodReturnsNewInstance(): void
    {
        $config = new TotpConfig();

        $changed = $config->withPeriod(60);

        $this->assertSame(60, $changed->period);
        $this->assertSame(30, $config->period);
        $this->assertSame(6, $changed->digits);
    }

    #[Test]
    public function testWithDigitsReturnsNewInstance(): void
    {
        $config = new TotpConfig();

        $changed = $config->withDigits(8);

        $this->assertSame(8, $changed->digits);
        $this->assertSame(6, $config->digits);
        $this->assertSame(30, $changed->period);
    }

    #[Test]
    public function testWithAlgorithmReturnsNewInstance(): void
    {
        $config = new TotpConfig();

        $changed = $config->withAlgorithm(TotpAlgorithm::Sha512);

        $this->assertSame(TotpAlgorithm::Sha512, $changed->algorithm);
        $this->assertSame(TotpAlgorithm::Sha1, $config->algorithm);
        $this->assertSame(1, $changed->window);
    }

    #[Test]
    public function testWithWindowReturnsNewInstance(): void
    {
        $config = new TotpConfig();

        $changed = $config->withWindow(2);

        $this->assertSame(2, $changed->window);
        $this->assertSame(1, $config->window);
        $this->assertSame(TotpAlgorithm::Sha1, $changed->algorithm);
    }
}
