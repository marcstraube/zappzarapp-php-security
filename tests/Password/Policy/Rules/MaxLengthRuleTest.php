<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Policy\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Policy\PolicyRule;
use Zappzarapp\Security\Password\Policy\Rules\MaxLengthRule;

#[CoversClass(MaxLengthRule::class)]
final class MaxLengthRuleTest extends TestCase
{
    public function testImplementsPolicyRuleInterface(): void
    {
        $rule = new MaxLengthRule();

        $this->assertInstanceOf(PolicyRule::class, $rule);
    }

    public function testDefaultMaxLength(): void
    {
        $rule = new MaxLengthRule();

        $this->assertSame(128, $rule->maxLength());
    }

    public function testCustomMaxLength(): void
    {
        $rule = new MaxLengthRule(72);

        $this->assertSame(72, $rule->maxLength());
    }

    public function testIsSatisfiedWithExactLength(): void
    {
        $rule = new MaxLengthRule(8);

        $this->assertTrue($rule->isSatisfied('12345678'));
    }

    public function testIsSatisfiedWithShorterPassword(): void
    {
        $rule = new MaxLengthRule(8);

        $this->assertTrue($rule->isSatisfied('1234'));
    }

    public function testIsNotSatisfiedWithLongerPassword(): void
    {
        $rule = new MaxLengthRule(8);

        $this->assertFalse($rule->isSatisfied('123456789'));
    }

    public function testIsSatisfiedWithEmptyPassword(): void
    {
        $rule = new MaxLengthRule(8);

        $this->assertTrue($rule->isSatisfied(''));
    }

    public function testIsNotSatisfiedWithZeroMaxLengthAndNonEmptyPassword(): void
    {
        $rule = new MaxLengthRule(0);

        $this->assertFalse($rule->isSatisfied('a'));
    }

    public function testIsSatisfiedWithZeroMaxLengthAndEmptyPassword(): void
    {
        $rule = new MaxLengthRule(0);

        $this->assertTrue($rule->isSatisfied(''));
    }

    public function testErrorMessage(): void
    {
        $rule = new MaxLengthRule(128);

        $this->assertSame(
            'Password must not exceed 128 characters',
            $rule->errorMessage()
        );
    }

    public function testErrorMessageWithDifferentLength(): void
    {
        $rule = new MaxLengthRule(72);

        $this->assertSame(
            'Password must not exceed 72 characters',
            $rule->errorMessage()
        );
    }

    public function testHandlesUnicodeCharacters(): void
    {
        $rule = new MaxLengthRule(4);

        $this->assertTrue($rule->isSatisfied('Test'));
        $this->assertFalse($rule->isSatisfied('Tests'));
    }

    public function testHandlesMultiByteCharacters(): void
    {
        $rule = new MaxLengthRule(6);

        $this->assertTrue($rule->isSatisfied('passwd'));
        $this->assertFalse($rule->isSatisfied('passwor'));
    }

    public function testHandlesEmojiCharacters(): void
    {
        $rule = new MaxLengthRule(4);

        $fourEmojis = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}";
        $fiveEmojis = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}";

        $this->assertTrue($rule->isSatisfied($fourEmojis));
        $this->assertFalse($rule->isSatisfied($fiveEmojis));
    }

    public function testHandlesWhitespace(): void
    {
        $rule = new MaxLengthRule(8);

        $this->assertTrue($rule->isSatisfied('        ')); // 8 spaces
        $this->assertFalse($rule->isSatisfied('         ')); // 9 spaces
    }

    public function testPreventsDoSWithVeryLongPassword(): void
    {
        $rule = new MaxLengthRule(128);

        $veryLongPassword = str_repeat('a', 10000);

        $this->assertFalse($rule->isSatisfied($veryLongPassword));
    }

    public function testBcryptLimit(): void
    {
        $rule = new MaxLengthRule(72);

        $this->assertTrue($rule->isSatisfied(str_repeat('a', 72)));
        $this->assertFalse($rule->isSatisfied(str_repeat('a', 73)));
    }

    /**
     * @return array<string, array{int, string, bool}>
     */
    public static function maxLengthProvider(): array
    {
        return [
            'exact match'          => [8, '12345678', true],
            'one under'            => [8, '1234567', true],
            'one over'             => [8, '123456789', false],
            'empty string'         => [8, '', true],
            'zero max empty'       => [0, '', true],
            'zero max non-empty'   => [0, 'a', false],
            'unicode at limit'     => [4, 'test', true],
            'unicode over limit'   => [4, 'tests', false],
        ];
    }

    #[DataProvider('maxLengthProvider')]
    public function testIsSatisfiedWithDataProvider(int $maxLength, string $password, bool $expected): void
    {
        $rule = new MaxLengthRule($maxLength);

        $this->assertSame($expected, $rule->isSatisfied($password));
    }
}
