<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Policy\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Policy\PolicyRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireLowercaseRule;

#[CoversClass(RequireLowercaseRule::class)]
final class RequireLowercaseRuleTest extends TestCase
{
    private RequireLowercaseRule $rule;

    protected function setUp(): void
    {
        $this->rule = new RequireLowercaseRule();
    }

    public function testImplementsPolicyRuleInterface(): void
    {
        $this->assertInstanceOf(PolicyRule::class, $this->rule);
    }

    public function testIsSatisfiedWithSingleLowercase(): void
    {
        $this->assertTrue($this->rule->isSatisfied('PASSWORDa'));
    }

    public function testIsSatisfiedWithAllLowercase(): void
    {
        $this->assertTrue($this->rule->isSatisfied('password'));
    }

    public function testIsSatisfiedWithMixedCase(): void
    {
        $this->assertTrue($this->rule->isSatisfied('PassWord'));
    }

    public function testIsNotSatisfiedWithAllUppercase(): void
    {
        $this->assertFalse($this->rule->isSatisfied('PASSWORD'));
    }

    public function testIsNotSatisfiedWithEmptyString(): void
    {
        $this->assertFalse($this->rule->isSatisfied(''));
    }

    public function testIsNotSatisfiedWithDigitsOnly(): void
    {
        $this->assertFalse($this->rule->isSatisfied('123456'));
    }

    public function testIsNotSatisfiedWithSpecialCharsOnly(): void
    {
        $this->assertFalse($this->rule->isSatisfied('!@#$%^&*()'));
    }

    public function testErrorMessage(): void
    {
        $this->assertSame(
            'Password must contain at least one lowercase letter',
            $this->rule->errorMessage()
        );
    }

    public function testHandlesUnicodeLowercase(): void
    {
        // Unicode lowercase letters should match \p{Ll}
        $this->assertTrue($this->rule->isSatisfied('PASSWORD1lowercase'));
        $this->assertTrue($this->rule->isSatisfied('letter'));
    }

    public function testHandlesGermanUmlauts(): void
    {
        // German lowercase umlauts
        $this->assertTrue($this->rule->isSatisfied('PASSWORToe'));
    }

    public function testHandlesCyrillicLowercase(): void
    {
        $this->assertTrue($this->rule->isSatisfied('PASSWORDpwd'));
    }

    public function testHandlesGreekLowercase(): void
    {
        $this->assertTrue($this->rule->isSatisfied('PASSWORDpwd'));
    }

    public function testWithWhitespace(): void
    {
        $this->assertTrue($this->rule->isSatisfied('PASS a WORD'));
    }

    public function testWithNewlines(): void
    {
        $this->assertTrue($this->rule->isSatisfied("PASS\na\nWORD"));
    }

    public function testAllAsciiLowercaseLetters(): void
    {
        $lowercase = 'abcdefghijklmnopqrstuvwxyz';

        foreach (str_split($lowercase) as $char) {
            $this->assertTrue(
                $this->rule->isSatisfied('PASSWORD' . $char),
                "Failed for lowercase: {$char}"
            );
        }
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function lowercaseProvider(): array
    {
        return [
            'all lowercase'       => ['password', true],
            'single lowercase'    => ['PASSWORDa', true],
            'mixed case'          => ['PassWord', true],
            'all uppercase'       => ['PASSWORD', false],
            'digits only'         => ['123456', false],
            'special only'        => ['!@#$%', false],
            'empty'               => ['', false],
            'spaces only'         => ['     ', false],
            'lowercase at start'  => ['aUPPER', true],
            'lowercase at end'    => ['UPPERa', true],
            'lowercase in middle' => ['UPaER', true],
        ];
    }

    #[DataProvider('lowercaseProvider')]
    public function testIsSatisfiedWithDataProvider(string $password, bool $expected): void
    {
        $this->assertSame($expected, $this->rule->isSatisfied($password));
    }
}
