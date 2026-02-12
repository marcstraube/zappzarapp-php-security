<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Policy\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Policy\PolicyRule;
use Zappzarapp\Security\Password\Policy\Rules\MinLengthRule;

#[CoversClass(MinLengthRule::class)]
final class MinLengthRuleTest extends TestCase
{
    public function testImplementsPolicyRuleInterface(): void
    {
        $rule = new MinLengthRule();

        $this->assertInstanceOf(PolicyRule::class, $rule);
    }

    public function testDefaultMinLength(): void
    {
        $rule = new MinLengthRule();

        $this->assertSame(12, $rule->minLength());
    }

    public function testCustomMinLength(): void
    {
        $rule = new MinLengthRule(8);

        $this->assertSame(8, $rule->minLength());
    }

    public function testIsSatisfiedWithExactLength(): void
    {
        $rule = new MinLengthRule(8);

        $this->assertTrue($rule->isSatisfied('12345678'));
    }

    public function testIsSatisfiedWithLongerPassword(): void
    {
        $rule = new MinLengthRule(8);

        $this->assertTrue($rule->isSatisfied('123456789012'));
    }

    public function testIsNotSatisfiedWithShorterPassword(): void
    {
        $rule = new MinLengthRule(8);

        $this->assertFalse($rule->isSatisfied('1234567'));
    }

    public function testIsNotSatisfiedWithEmptyPassword(): void
    {
        $rule = new MinLengthRule(8);

        $this->assertFalse($rule->isSatisfied(''));
    }

    public function testIsSatisfiedWithEmptyPasswordAndZeroMinLength(): void
    {
        $rule = new MinLengthRule(0);

        $this->assertTrue($rule->isSatisfied(''));
    }

    public function testErrorMessage(): void
    {
        $rule = new MinLengthRule(8);

        $this->assertSame(
            'Password must be at least 8 characters',
            $rule->errorMessage()
        );
    }

    public function testErrorMessageWithDifferentLength(): void
    {
        $rule = new MinLengthRule(16);

        $this->assertSame(
            'Password must be at least 16 characters',
            $rule->errorMessage()
        );
    }

    public function testHandlesUnicodeCharacters(): void
    {
        $rule = new MinLengthRule(4);

        // Unicode characters should be counted as single characters
        $this->assertTrue($rule->isSatisfied('Test'));
        $this->assertTrue($rule->isSatisfied('test'));
    }

    public function testHandlesMultiByteCharacters(): void
    {
        $rule = new MinLengthRule(6);

        // 6 unicode characters
        $this->assertTrue($rule->isSatisfied('passwd'));
        $this->assertFalse($rule->isSatisfied('passw'));
    }

    public function testHandlesEmojiCharacters(): void
    {
        $rule = new MinLengthRule(4);

        // Emojis are multi-byte but should count as single characters
        $emoji = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}"; // 4 emojis
        $this->assertTrue($rule->isSatisfied($emoji));
    }

    public function testHandlesWhitespace(): void
    {
        $rule = new MinLengthRule(8);

        $this->assertTrue($rule->isSatisfied('        ')); // 8 spaces
        $this->assertFalse($rule->isSatisfied('       ')); // 7 spaces
    }

    /**
     * @return array<string, array{int, string, bool}>
     */
    public static function minLengthProvider(): array
    {
        return [
            'exact match'         => [8, '12345678', true],
            'one over'            => [8, '123456789', true],
            'one under'           => [8, '1234567', false],
            'empty string'        => [8, '', false],
            'zero min empty'      => [0, '', true],
            'zero min non-empty'  => [0, 'a', true],
            'unicode 4 chars'     => [4, 'pass', true],
            'unicode 3 chars'     => [4, 'pas', false],
        ];
    }

    #[DataProvider('minLengthProvider')]
    public function testIsSatisfiedWithDataProvider(int $minLength, string $password, bool $expected): void
    {
        $rule = new MinLengthRule($minLength);

        $this->assertSame($expected, $rule->isSatisfied($password));
    }
}
