<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Policy\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Policy\PolicyRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireSpecialCharRule;

#[CoversClass(RequireSpecialCharRule::class)]
final class RequireSpecialCharRuleTest extends TestCase
{
    private RequireSpecialCharRule $rule;

    protected function setUp(): void
    {
        $this->rule = new RequireSpecialCharRule();
    }

    public function testImplementsPolicyRuleInterface(): void
    {
        $this->assertInstanceOf(PolicyRule::class, $this->rule);
    }

    public function testDefaultSpecialChars(): void
    {
        $expected = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\`~';

        $this->assertSame($expected, $this->rule->specialChars());
    }

    public function testCustomSpecialChars(): void
    {
        $rule = new RequireSpecialCharRule('!@#');

        $this->assertSame('!@#', $rule->specialChars());
    }

    public function testIsSatisfiedWithSingleSpecialChar(): void
    {
        $this->assertTrue($this->rule->isSatisfied('password!'));
    }

    public function testIsSatisfiedWithMultipleSpecialChars(): void
    {
        $this->assertTrue($this->rule->isSatisfied('p@ssw!rd#'));
    }

    public function testIsSatisfiedWithOnlySpecialChars(): void
    {
        $this->assertTrue($this->rule->isSatisfied('!@#$%'));
    }

    public function testIsNotSatisfiedWithNoSpecialChars(): void
    {
        $this->assertFalse($this->rule->isSatisfied('password123'));
    }

    public function testIsNotSatisfiedWithEmptyString(): void
    {
        $this->assertFalse($this->rule->isSatisfied(''));
    }

    public function testIsNotSatisfiedWithOnlyLetters(): void
    {
        $this->assertFalse($this->rule->isSatisfied('PasswordOnly'));
    }

    public function testIsNotSatisfiedWithOnlyDigits(): void
    {
        $this->assertFalse($this->rule->isSatisfied('123456'));
    }

    public function testErrorMessage(): void
    {
        $this->assertSame(
            'Password must contain at least one special character',
            $this->rule->errorMessage()
        );
    }

    public function testAllDefaultSpecialChars(): void
    {
        $specialChars = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\`~';

        foreach (mb_str_split($specialChars) as $char) {
            $this->assertTrue(
                $this->rule->isSatisfied('password' . $char),
                "Failed for special char: {$char}"
            );
        }
    }

    public function testCustomSpecialCharsRule(): void
    {
        $rule = new RequireSpecialCharRule('!@#');

        $this->assertTrue($rule->isSatisfied('password!'));
        $this->assertTrue($rule->isSatisfied('password@'));
        $this->assertTrue($rule->isSatisfied('password#'));
        $this->assertFalse($rule->isSatisfied('password$'));
        $this->assertFalse($rule->isSatisfied('password%'));
    }

    public function testWithWhitespace(): void
    {
        // Space is not in default special chars
        $this->assertFalse($this->rule->isSatisfied('pass word'));
        $this->assertTrue($this->rule->isSatisfied('pass! word'));
    }

    public function testWithUnicodeCharacters(): void
    {
        // Unicode special characters not in the default list
        $this->assertFalse($this->rule->isSatisfied('password'));
        $this->assertTrue($this->rule->isSatisfied('password!'));
    }

    public function testSpecialCharAtDifferentPositions(): void
    {
        $this->assertTrue($this->rule->isSatisfied('!password'));
        $this->assertTrue($this->rule->isSatisfied('pass!word'));
        $this->assertTrue($this->rule->isSatisfied('password!'));
    }

    public function testEmptyCustomSpecialChars(): void
    {
        $rule = new RequireSpecialCharRule('');

        // With empty special chars list, nothing satisfies it
        $this->assertFalse($rule->isSatisfied('password!@#'));
        $this->assertFalse($rule->isSatisfied(''));
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function specialCharProvider(): array
    {
        return [
            'exclamation'      => ['password!', true],
            'at sign'          => ['pass@word', true],
            'hash'             => ['#password', true],
            'dollar'           => ['pass$word', true],
            'percent'          => ['pass%word', true],
            'caret'            => ['pass^word', true],
            'ampersand'        => ['pass&word', true],
            'asterisk'         => ['pass*word', true],
            'parentheses'      => ['pass()word', true],
            'underscore'       => ['pass_word', true],
            'plus'             => ['pass+word', true],
            'minus'            => ['pass-word', true],
            'equals'           => ['pass=word', true],
            'brackets'         => ['pass[]word', true],
            'braces'           => ['pass{}word', true],
            'pipe'             => ['pass|word', true],
            'semicolon'        => ['pass;word', true],
            'colon'            => ['pass:word', true],
            'single quote'     => ["pass'word", true],
            'double quote'     => ['pass"word', true],
            'comma'            => ['pass,word', true],
            'period'           => ['pass.word', true],
            'less than'        => ['pass<word', true],
            'greater than'     => ['pass>word', true],
            'question mark'    => ['pass?word', true],
            'forward slash'    => ['pass/word', true],
            'backslash'        => ['pass\\word', true],
            'backtick'         => ['pass`word', true],
            'tilde'            => ['pass~word', true],
            'no special'       => ['password123', false],
            'empty'            => ['', false],
            'letters only'     => ['Password', false],
            'digits only'      => ['123456', false],
        ];
    }

    #[DataProvider('specialCharProvider')]
    public function testIsSatisfiedWithDataProvider(string $password, bool $expected): void
    {
        $this->assertSame($expected, $this->rule->isSatisfied($password));
    }
}
