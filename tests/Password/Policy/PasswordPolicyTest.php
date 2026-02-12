<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Policy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Policy\PasswordPolicy;
use Zappzarapp\Security\Password\Policy\PolicyRule;
use Zappzarapp\Security\Password\Policy\Rules\MaxLengthRule;
use Zappzarapp\Security\Password\Policy\Rules\MinLengthRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireDigitRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireLowercaseRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireSpecialCharRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireUppercaseRule;

#[CoversClass(PasswordPolicy::class)]
final class PasswordPolicyTest extends TestCase
{
    public function testDefaultConstructorCreatesEmptyPolicy(): void
    {
        $policy = new PasswordPolicy();

        $this->assertSame([], $policy->rules());
    }

    public function testConstructorWithRules(): void
    {
        $rules = [
            new MinLengthRule(8),
            new MaxLengthRule(128),
        ];

        $policy = new PasswordPolicy($rules);

        $this->assertCount(2, $policy->rules());
    }

    public function testWithRuleReturnsNewInstance(): void
    {
        $original = new PasswordPolicy();
        $modified = $original->withRule(new MinLengthRule(8));

        $this->assertNotSame($original, $modified);
        $this->assertSame([], $original->rules());
        $this->assertCount(1, $modified->rules());
    }

    public function testWithRuleAddsRuleToEnd(): void
    {
        $policy = (new PasswordPolicy())
            ->withRule(new MinLengthRule(8))
            ->withRule(new MaxLengthRule(128));

        $rules = $policy->rules();

        $this->assertCount(2, $rules);
        $this->assertInstanceOf(MinLengthRule::class, $rules[0]);
        $this->assertInstanceOf(MaxLengthRule::class, $rules[1]);
    }

    public function testValidateReturnsEmptyArrayForValidPassword(): void
    {
        $policy = (new PasswordPolicy())
            ->withRule(new MinLengthRule(8))
            ->withRule(new MaxLengthRule(128));

        $violations = $policy->validate('ValidPassword123');

        $this->assertSame([], $violations);
    }

    public function testValidateReturnsSingleViolation(): void
    {
        $policy = (new PasswordPolicy())
            ->withRule(new MinLengthRule(8));

        $violations = $policy->validate('short');

        $this->assertCount(1, $violations);
        $this->assertStringContainsString('at least 8 characters', $violations[0]);
    }

    public function testValidateReturnsMultipleViolations(): void
    {
        $policy = (new PasswordPolicy())
            ->withRule(new MinLengthRule(8))
            ->withRule(new RequireUppercaseRule())
            ->withRule(new RequireDigitRule());

        $violations = $policy->validate('short');

        $this->assertCount(3, $violations);
    }

    public function testIsValidReturnsTrueForValidPassword(): void
    {
        $policy = (new PasswordPolicy())
            ->withRule(new MinLengthRule(8))
            ->withRule(new MaxLengthRule(128));

        $this->assertTrue($policy->isValid('ValidPassword123'));
    }

    public function testIsValidReturnsFalseForInvalidPassword(): void
    {
        $policy = (new PasswordPolicy())
            ->withRule(new MinLengthRule(8));

        $this->assertFalse($policy->isValid('short'));
    }

    public function testIsValidWithEmptyPolicyReturnsTrue(): void
    {
        $policy = new PasswordPolicy();

        $this->assertTrue($policy->isValid(''));
        $this->assertTrue($policy->isValid('anypassword'));
    }

    public function testNistPolicyConfiguration(): void
    {
        $policy = PasswordPolicy::nist();
        $rules  = $policy->rules();

        $this->assertCount(2, $rules);
        $this->assertInstanceOf(MinLengthRule::class, $rules[0]);
        $this->assertInstanceOf(MaxLengthRule::class, $rules[1]);

        // NIST recommends 12 char minimum, 128 max
        /** @var MinLengthRule $minRule */
        $minRule = $rules[0];
        /** @var MaxLengthRule $maxRule */
        $maxRule = $rules[1];

        $this->assertSame(12, $minRule->minLength());
        $this->assertSame(128, $maxRule->maxLength());
    }

    public function testNistPolicyValidation(): void
    {
        $policy = PasswordPolicy::nist();

        $this->assertTrue($policy->isValid('LongEnoughPassword'));
        $this->assertFalse($policy->isValid('short'));
    }

    public function testStrictPolicyConfiguration(): void
    {
        $policy = PasswordPolicy::strict();
        $rules  = $policy->rules();

        $this->assertCount(6, $rules);
        $this->assertInstanceOf(MinLengthRule::class, $rules[0]);
        $this->assertInstanceOf(MaxLengthRule::class, $rules[1]);
        $this->assertInstanceOf(RequireUppercaseRule::class, $rules[2]);
        $this->assertInstanceOf(RequireLowercaseRule::class, $rules[3]);
        $this->assertInstanceOf(RequireDigitRule::class, $rules[4]);
        $this->assertInstanceOf(RequireSpecialCharRule::class, $rules[5]);
    }

    public function testStrictPolicyValidation(): void
    {
        $policy = PasswordPolicy::strict();

        // Meets all requirements
        $this->assertTrue($policy->isValid('SecureP@ss123!'));

        // Missing uppercase
        $this->assertFalse($policy->isValid('securep@ss123!'));

        // Missing lowercase
        $this->assertFalse($policy->isValid('SECUREP@SS123!'));

        // Missing digit
        $this->assertFalse($policy->isValid('SecureP@ssword!'));

        // Missing special char
        $this->assertFalse($policy->isValid('SecurePass1234'));

        // Too short
        $this->assertFalse($policy->isValid('Short1!'));
    }

    public function testLegacyPolicyConfiguration(): void
    {
        $policy = PasswordPolicy::legacy();
        $rules  = $policy->rules();

        $this->assertCount(2, $rules);

        /** @var MinLengthRule $minRule */
        $minRule = $rules[0];
        /** @var MaxLengthRule $maxRule */
        $maxRule = $rules[1];

        $this->assertSame(8, $minRule->minLength());
        $this->assertSame(72, $maxRule->maxLength()); // bcrypt limit
    }

    public function testLegacyPolicyValidation(): void
    {
        $policy = PasswordPolicy::legacy();

        $this->assertTrue($policy->isValid('password'));
        $this->assertFalse($policy->isValid('short'));
        $this->assertFalse($policy->isValid(str_repeat('a', 73)));
    }

    public function testEmptyPolicyStaticFactory(): void
    {
        $policy = PasswordPolicy::empty();

        $this->assertSame([], $policy->rules());
        $this->assertTrue($policy->isValid(''));
        $this->assertTrue($policy->isValid('anything'));
    }

    public function testPolicyIsImmutable(): void
    {
        $policy1 = new PasswordPolicy();
        $policy2 = $policy1->withRule(new MinLengthRule(8));
        $policy3 = $policy2->withRule(new MaxLengthRule(128));

        $this->assertSame([], $policy1->rules());
        $this->assertCount(1, $policy2->rules());
        $this->assertCount(2, $policy3->rules());
    }

    public function testValidateWithUnicodePassword(): void
    {
        $policy = PasswordPolicy::nist();

        // Unicode password with 12+ characters
        $this->assertTrue($policy->isValid('SecurePassword'));
    }

    public function testValidateWithVeryLongPassword(): void
    {
        $policy = (new PasswordPolicy())
            ->withRule(new MaxLengthRule(128));

        $longPassword = str_repeat('a', 200);

        $violations = $policy->validate($longPassword);

        $this->assertCount(1, $violations);
        $this->assertStringContainsString('must not exceed', $violations[0]);
    }

    public function testValidateWithEmptyPassword(): void
    {
        $policy = PasswordPolicy::strict();

        $violations = $policy->validate('');

        // Should fail multiple rules
        $this->assertGreaterThan(1, count($violations));
    }

    public function testRulesReturnsList(): void
    {
        $policy = (new PasswordPolicy())
            ->withRule(new MinLengthRule(8))
            ->withRule(new MaxLengthRule(128));

        $rules = $policy->rules();

        // Verify it's a list (sequential array)
        $this->assertSame([0, 1], array_keys($rules));
    }

    public function testCustomRule(): void
    {
        $customRule = new class () implements PolicyRule {
            public function isSatisfied(string $password): bool
            {
                return !str_contains($password, 'password');
            }

            public function errorMessage(): string
            {
                return 'Password cannot contain the word "password"';
            }
        };

        $policy = (new PasswordPolicy())->withRule($customRule);

        $this->assertTrue($policy->isValid('SecureP@ss123'));
        $this->assertFalse($policy->isValid('password123'));
    }
}
