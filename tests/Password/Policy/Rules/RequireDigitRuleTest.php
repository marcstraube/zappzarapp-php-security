<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Policy\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Policy\PolicyRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireDigitRule;

#[CoversClass(RequireDigitRule::class)]
final class RequireDigitRuleTest extends TestCase
{
    private RequireDigitRule $rule;

    protected function setUp(): void
    {
        $this->rule = new RequireDigitRule();
    }

    #[Test]
    public function testImplementsPolicyRuleInterface(): void
    {
        $this->assertInstanceOf(PolicyRule::class, $this->rule);
    }

    #[Test]
    public function testIsSatisfiedWithSingleDigit(): void
    {
        $this->assertTrue($this->rule->isSatisfied('password1'));
    }

    #[Test]
    public function testIsSatisfiedWithMultipleDigits(): void
    {
        $this->assertTrue($this->rule->isSatisfied('pass123word'));
    }

    #[Test]
    public function testIsSatisfiedWithOnlyDigits(): void
    {
        $this->assertTrue($this->rule->isSatisfied('123456'));
    }

    #[Test]
    public function testIsSatisfiedWithDigitAtStart(): void
    {
        $this->assertTrue($this->rule->isSatisfied('1password'));
    }

    #[Test]
    public function testIsSatisfiedWithDigitAtEnd(): void
    {
        $this->assertTrue($this->rule->isSatisfied('password9'));
    }

    #[Test]
    public function testIsNotSatisfiedWithNoDigits(): void
    {
        $this->assertFalse($this->rule->isSatisfied('passwordonly'));
    }

    #[Test]
    public function testIsNotSatisfiedWithEmptyString(): void
    {
        $this->assertFalse($this->rule->isSatisfied(''));
    }

    #[Test]
    public function testIsNotSatisfiedWithOnlyLetters(): void
    {
        $this->assertFalse($this->rule->isSatisfied('ABCDEFGhijklmn'));
    }

    #[Test]
    public function testIsNotSatisfiedWithSpecialCharsOnly(): void
    {
        $this->assertFalse($this->rule->isSatisfied('!@#$%^&*()'));
    }

    #[Test]
    public function testErrorMessage(): void
    {
        $this->assertSame(
            'Password must contain at least one digit',
            $this->rule->errorMessage()
        );
    }

    #[Test]
    public function testAllDigits(): void
    {
        $digits = '0123456789';

        for ($i = 0; $i < 10; $i++) {
            $password = 'password' . $digits[$i];
            $this->assertTrue(
                $this->rule->isSatisfied($password),
                "Failed for digit: {$digits[$i]}"
            );
        }
    }

    #[Test]
    public function testDoesNotMatchUnicodeDigits(): void
    {
        // Full-width digits should not match \d
        // But actually \d in PHP PCRE does match ASCII digits only
        $fullWidthDigit = "\u{FF11}"; // Full-width 1
        $this->assertFalse($this->rule->isSatisfied('password' . $fullWidthDigit));
    }

    #[Test]
    public function testWithWhitespace(): void
    {
        $this->assertTrue($this->rule->isSatisfied('pass 1 word'));
    }

    #[Test]
    public function testWithNewlines(): void
    {
        $this->assertTrue($this->rule->isSatisfied("pass\n1\nword"));
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function digitProvider(): array
    {
        return [
            'single digit 0'       => ['password0', true],
            'single digit 5'       => ['pass5word', true],
            'single digit 9'       => ['9password', true],
            'multiple digits'      => ['p4ssw0rd', true],
            'only digits'          => ['12345', true],
            'letters only'         => ['password', false],
            'special chars only'   => ['!@#$%', false],
            'empty'                => ['', false],
            'spaces only'          => ['     ', false],
            'mixed with special'   => ['p@ss1word!', true],
        ];
    }

    #[DataProvider('digitProvider')]
    #[Test]
    public function testIsSatisfiedWithDataProvider(string $password, bool $expected): void
    {
        $this->assertSame($expected, $this->rule->isSatisfied($password));
    }
}
