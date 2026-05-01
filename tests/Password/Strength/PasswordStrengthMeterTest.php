<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Strength;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Strength\PasswordStrengthMeter;
use Zappzarapp\Security\Password\Strength\StrengthLevel;

#[CoversClass(PasswordStrengthMeter::class)]
final class PasswordStrengthMeterTest extends TestCase
{
    private PasswordStrengthMeter $meter;

    protected function setUp(): void
    {
        $this->meter = new PasswordStrengthMeter();
    }

    #[Test]
    public function testMeasureReturnsCorrectStructure(): void
    {
        $result = $this->meter->measure('TestPassword123!');

        $this->assertArrayHasKey('level', $result);
        $this->assertArrayHasKey('entropy', $result);
        $this->assertArrayHasKey('feedback', $result);
        $this->assertInstanceOf(StrengthLevel::class, $result['level']);
        $this->assertIsFloat($result['entropy']);
        $this->assertIsArray($result['feedback']);
    }

    #[Test]
    public function testMeasureWithEmptyPassword(): void
    {
        $result = $this->meter->measure('');

        $this->assertSame(StrengthLevel::VERY_WEAK, $result['level']);
        $this->assertSame(0.0, $result['entropy']);
    }

    #[Test]
    public function testMeasureWithWeakPassword(): void
    {
        $result = $this->meter->measure('abc');

        $this->assertSame(StrengthLevel::VERY_WEAK, $result['level']);
        $this->assertNotEmpty($result['feedback']);
    }

    #[Test]
    public function testMeasureWithStrongPassword(): void
    {
        // 11 chars with mixed charset (~72 bits entropy) = STRONG (60-79 bits)
        $result = $this->meter->measure('Abc123!@#Xy');

        $this->assertSame(StrengthLevel::STRONG, $result['level']);
        $this->assertSame([], $result['feedback']);
    }

    #[Test]
    public function testLevelReturnsStrengthLevel(): void
    {
        $level = $this->meter->level('TestPassword123!');

        $this->assertInstanceOf(StrengthLevel::class, $level);
    }

    #[Test]
    public function testLevelWithVeryWeakPassword(): void
    {
        $this->assertSame(StrengthLevel::VERY_WEAK, $this->meter->level('abc'));
    }

    #[Test]
    public function testLevelWithVeryStrongPassword(): void
    {
        // Long mixed-case password for testing very strong level (not a real password)
        $password = 'Test' . str_repeat('Aa1!', 8);
        $this->assertSame(StrengthLevel::VERY_STRONG, $this->meter->level($password));
    }

    #[Test]
    public function testEntropyReturnsFloat(): void
    {
        $entropy = $this->meter->entropy('TestPassword');

        $this->assertIsFloat($entropy);
    }

    #[Test]
    public function testEntropyWithEmptyPassword(): void
    {
        $this->assertSame(0.0, $this->meter->entropy(''));
    }

    #[Test]
    public function testEntropyIncreasesWithLength(): void
    {
        $short = $this->meter->entropy('abc');
        $long  = $this->meter->entropy('abcdefghijkl');

        $this->assertGreaterThan($short, $long);
    }

    #[Test]
    public function testEntropyIncreasesWithCharacterDiversity(): void
    {
        $lowerOnly = $this->meter->entropy('abcdefgh');
        $mixed     = $this->meter->entropy('Abcd1234');

        $this->assertGreaterThan($lowerOnly, $mixed);
    }

    #[Test]
    public function testMeetsMinimumReturnsTrueWhenMet(): void
    {
        $this->assertTrue($this->meter->meetsMinimum('TestPass123!', StrengthLevel::FAIR));
    }

    #[Test]
    public function testMeetsMinimumReturnsFalseWhenNotMet(): void
    {
        $this->assertFalse($this->meter->meetsMinimum('abc', StrengthLevel::STRONG));
    }

    #[Test]
    public function testMeetsMinimumWithExactLevel(): void
    {
        // FAIR password should meet FAIR requirement
        $password = 'Abcd1234';
        $level    = $this->meter->level($password);

        $this->assertTrue($this->meter->meetsMinimum($password, $level));
    }

    #[Test]
    public function testFeedbackForShortPassword(): void
    {
        $result = $this->meter->measure('Abc1!');

        $this->assertContains('Use at least 12 characters', $result['feedback']);
    }

    #[Test]
    public function testFeedbackForMediumLengthPassword(): void
    {
        // 12-15 characters should get "consider using more" feedback if not strong
        $result = $this->meter->measure('abcdefghijkl');

        $this->assertContains('Consider using more characters for better security', $result['feedback']);
    }

    #[Test]
    public function testFeedbackForMissingUppercase(): void
    {
        // Use a password that is FAIR level (not STRONG) so feedback is generated
        $result = $this->meter->measure('lower1!');

        $this->assertContains('Add uppercase letters', $result['feedback']);
    }

    #[Test]
    public function testFeedbackForMissingLowercase(): void
    {
        // Use a password that is FAIR level (not STRONG) so feedback is generated
        $result = $this->meter->measure('UPPER1!');

        $this->assertContains('Add lowercase letters', $result['feedback']);
    }

    #[Test]
    public function testFeedbackForMissingDigits(): void
    {
        // Use a password that is FAIR level (not STRONG) so feedback is generated
        $result = $this->meter->measure('NoD!@#');

        $this->assertContains('Add numbers', $result['feedback']);
    }

    #[Test]
    public function testFeedbackForMissingSpecialChars(): void
    {
        // Use a password that is FAIR level (not STRONG) so feedback is generated
        $result = $this->meter->measure('NoSpec12');

        $this->assertContains('Add special characters', $result['feedback']);
    }

    #[Test]
    public function testFeedbackForRepeatingPattern(): void
    {
        $result = $this->meter->measure('abcabc');

        $this->assertContains('Avoid repeating patterns', $result['feedback']);
    }

    #[Test]
    public function testFeedbackForSequentialPattern(): void
    {
        $result = $this->meter->measure('abcdefgh');

        $this->assertContains('Avoid sequential characters', $result['feedback']);
    }

    #[Test]
    public function testNoFeedbackForStrongPassword(): void
    {
        $result = $this->meter->measure('Abcd1234!@#$XyZ');

        $this->assertSame([], $result['feedback']);
    }

    #[Test]
    public function testRepeatingPatternDetection(): void
    {
        $result1 = $this->meter->measure('abab');
        $result2 = $this->meter->measure('abcabcabc');

        $this->assertContains('Avoid repeating patterns', $result1['feedback']);
        $this->assertContains('Avoid repeating patterns', $result2['feedback']);
    }

    #[Test]
    public function testSequentialPatternDetection(): void
    {
        // Sequential numbers
        $result1 = $this->meter->measure('12345678');
        $this->assertContains('Avoid sequential characters', $result1['feedback']);

        // Sequential letters
        $result2 = $this->meter->measure('abcdefgh');
        $this->assertContains('Avoid sequential characters', $result2['feedback']);
    }

    #[Test]
    public function testNoSequentialPatternForShortSequences(): void
    {
        // Less than 4 sequential characters should not trigger
        $result = $this->meter->measure('ab12cd');

        $this->assertNotContains('Avoid sequential characters', $result['feedback']);
    }

    #[Test]
    public function testMeasureWithUnicodePassword(): void
    {
        $result = $this->meter->measure('SecurePassword');

        $this->assertArrayHasKey('level', $result);
        $this->assertArrayHasKey('entropy', $result);
    }

    #[Test]
    public function testMeasureWithSpecialCharacters(): void
    {
        $result = $this->meter->measure('P@ss!word#123$');

        $this->assertIsFloat($result['entropy']);
        $this->assertGreaterThan(0, $result['entropy']);
    }

    /**
     * @return array<string, array{string, StrengthLevel}>
     */
    public static function strengthLevelProvider(): array
    {
        return [
            'empty'       => ['', StrengthLevel::VERY_WEAK],
            'very short'  => ['ab', StrengthLevel::VERY_WEAK],
            'short lower' => ['abcdefg', StrengthLevel::WEAK],
            'medium'      => ['abcdefgh', StrengthLevel::FAIR],
            'mixed'       => ['Abcd1234!@#', StrengthLevel::STRONG],
        ];
    }

    #[DataProvider('strengthLevelProvider')]
    #[Test]
    public function testLevelWithDataProvider(string $password, StrengthLevel $expected): void
    {
        $this->assertSame($expected, $this->meter->level($password));
    }
}
