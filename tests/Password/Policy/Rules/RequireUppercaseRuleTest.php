<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Policy\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Policy\PolicyRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireUppercaseRule;

#[CoversClass(RequireUppercaseRule::class)]
final class RequireUppercaseRuleTest extends TestCase
{
    private RequireUppercaseRule $rule;

    protected function setUp(): void
    {
        $this->rule = new RequireUppercaseRule();
    }

    #[Test]
    public function testImplementsPolicyRuleInterface(): void
    {
        $this->assertInstanceOf(PolicyRule::class, $this->rule);
    }

    #[Test]
    public function testIsSatisfiedWithSingleUppercase(): void
    {
        $this->assertTrue($this->rule->isSatisfied('passwordA'));
    }

    #[Test]
    public function testIsSatisfiedWithAllUppercase(): void
    {
        $this->assertTrue($this->rule->isSatisfied('PASSWORD'));
    }

    #[Test]
    public function testIsSatisfiedWithMixedCase(): void
    {
        $this->assertTrue($this->rule->isSatisfied('PassWord'));
    }

    #[Test]
    public function testIsNotSatisfiedWithAllLowercase(): void
    {
        $this->assertFalse($this->rule->isSatisfied('password'));
    }

    #[Test]
    public function testIsNotSatisfiedWithEmptyString(): void
    {
        $this->assertFalse($this->rule->isSatisfied(''));
    }

    #[Test]
    public function testIsNotSatisfiedWithDigitsOnly(): void
    {
        $this->assertFalse($this->rule->isSatisfied('123456'));
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
            'Password must contain at least one uppercase letter',
            $this->rule->errorMessage()
        );
    }

    #[Test]
    public function testHandlesUnicodeUppercase(): void
    {
        // Unicode uppercase letters should match \p{Lu}
        $this->assertTrue($this->rule->isSatisfied('passwortP'));
    }

    #[Test]
    public function testHandlesGermanUmlauts(): void
    {
        // German uppercase umlauts
        $this->assertTrue($this->rule->isSatisfied('passwortOE'));
    }

    #[Test]
    public function testWithWhitespace(): void
    {
        $this->assertTrue($this->rule->isSatisfied('pass A word'));
    }

    #[Test]
    public function testWithNewlines(): void
    {
        $this->assertTrue($this->rule->isSatisfied("pass\nA\nword"));
    }

    #[Test]
    public function testAllAsciiUppercaseLetters(): void
    {
        $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

        foreach (str_split($uppercase) as $char) {
            $this->assertTrue(
                $this->rule->isSatisfied('password' . $char),
                "Failed for uppercase: {$char}"
            );
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function uppercaseProvider(): array
    {
        return [
            'all uppercase'       => ['PASSWORD', true],
            'single uppercase'    => ['passwordA', true],
            'mixed case'          => ['PassWord', true],
            'all lowercase'       => ['password', false],
            'digits only'         => ['123456', false],
            'special only'        => ['!@#$%', false],
            'empty'               => ['', false],
            'spaces only'         => ['     ', false],
            'uppercase at start'  => ['Alower', true],
            'uppercase at end'    => ['lowerA', true],
            'uppercase in middle' => ['loAer', true],
        ];
    }

    #[DataProvider('uppercaseProvider')]
    #[Test]
    public function testIsSatisfiedWithDataProvider(string $password, bool $expected): void
    {
        $this->assertSame($expected, $this->rule->isSatisfied($password));
    }
}
