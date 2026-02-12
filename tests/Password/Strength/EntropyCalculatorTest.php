<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Strength;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Strength\EntropyCalculator;
use Zappzarapp\Security\Password\Strength\StrengthLevel;

#[CoversClass(EntropyCalculator::class)]
final class EntropyCalculatorTest extends TestCase
{
    private EntropyCalculator $calculator;

    protected function setUp(): void
    {
        $this->calculator = new EntropyCalculator();
    }

    public function testEmptyPasswordReturnsZeroEntropy(): void
    {
        $entropy = $this->calculator->calculate('');

        $this->assertSame(0.0, $entropy);
    }

    public function testLowercaseOnlyPassword(): void
    {
        $entropy = $this->calculator->calculate('abcdef');

        $this->assertGreaterThan(0, $entropy);
        $this->assertLessThan(50, $entropy);
    }

    public function testMixedCasePassword(): void
    {
        $entropy = $this->calculator->calculate('AbCdEf');

        $this->assertGreaterThan(0, $entropy);
    }

    public function testAlphanumericPassword(): void
    {
        $entropy = $this->calculator->calculate('Abc123');

        $this->assertGreaterThan(0, $entropy);
    }

    public function testPasswordWithSpecialChars(): void
    {
        $entropy = $this->calculator->calculate('Abc123!@#');

        $this->assertGreaterThan(30, $entropy);
    }

    public function testPasswordWithSpace(): void
    {
        $entropy = $this->calculator->calculate('hello world');

        $this->assertGreaterThan(0, $entropy);
    }

    public function testPasswordWithUnicode(): void
    {
        $entropy = $this->calculator->calculate('пароль');

        $this->assertGreaterThan(0, $entropy);
    }

    public function testLongerPasswordHasMoreEntropy(): void
    {
        $shortEntropy = $this->calculator->calculate('abc');
        $longEntropy  = $this->calculator->calculate('abcdefghij');

        $this->assertGreaterThan($shortEntropy, $longEntropy);
    }

    public function testStrengthLevelVeryWeak(): void
    {
        $level = $this->calculator->strengthLevel('abc');

        $this->assertSame(StrengthLevel::VERY_WEAK, $level);
    }

    public function testStrengthLevelWeak(): void
    {
        $level = $this->calculator->strengthLevel('abcdefg');

        $this->assertSame(StrengthLevel::WEAK, $level);
    }

    public function testStrengthLevelFair(): void
    {
        $level = $this->calculator->strengthLevel('Abcd1234');

        $this->assertSame(StrengthLevel::FAIR, $level);
    }

    public function testStrengthLevelStrong(): void
    {
        // 11 chars with mixed charset (~72 bits entropy) = STRONG (60-79 bits)
        $level = $this->calculator->strengthLevel('Abc123!@#Xy');

        $this->assertSame(StrengthLevel::STRONG, $level);
    }

    public function testStrengthLevelVeryStrong(): void
    {
        $level = $this->calculator->strengthLevel('Abcd1234!@#$XyZmnop1234567890ABCDEF');

        $this->assertSame(StrengthLevel::VERY_STRONG, $level);
    }

    /**
     * @return array<string, array{string, StrengthLevel}>
     */
    public static function strengthLevelProvider(): array
    {
        // Entropy calculation: length * log2(poolSize)
        // 'abcdefgh': 8 * log2(26) = 37.6 bits = FAIR (36-60)
        // 'abcdef': 6 * log2(26) = 28.2 bits = WEAK (28-36)
        return [
            'empty'       => ['', StrengthLevel::VERY_WEAK],
            'short'       => ['ab', StrengthLevel::VERY_WEAK],
            'weak'        => ['abcdef', StrengthLevel::WEAK],
            'fair'        => ['abcdefgh', StrengthLevel::FAIR],
        ];
    }

    #[DataProvider('strengthLevelProvider')]
    public function testStrengthLevels(string $password, StrengthLevel $expected): void
    {
        $level = $this->calculator->strengthLevel($password);

        $this->assertSame($expected, $level);
    }
}
