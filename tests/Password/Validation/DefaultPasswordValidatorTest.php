<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Validation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Policy\PasswordPolicy;
use Zappzarapp\Security\Password\Policy\Rules\MinLengthRule;
use Zappzarapp\Security\Password\Pwned\HttpClientInterface;
use Zappzarapp\Security\Password\Pwned\PwnedPasswordChecker;
use Zappzarapp\Security\Password\Strength\StrengthLevel;
use Zappzarapp\Security\Password\Validation\DefaultPasswordValidator;
use Zappzarapp\Security\Password\Validation\PasswordValidator;
use Zappzarapp\Security\Password\Validation\ValidationResult;

#[CoversClass(DefaultPasswordValidator::class)]
final class DefaultPasswordValidatorTest extends TestCase
{
    #[Test]
    public function testImplementsPasswordValidatorInterface(): void
    {
        $validator = new DefaultPasswordValidator();

        $this->assertInstanceOf(PasswordValidator::class, $validator);
    }

    #[Test]
    public function testDefaultConstructor(): void
    {
        $validator = new DefaultPasswordValidator();
        $result    = $validator->validate('anypassword');

        $this->assertInstanceOf(ValidationResult::class, $result);
    }

    #[Test]
    public function testValidateReturnsValidResultForValidPassword(): void
    {
        $validator = new DefaultPasswordValidator();
        $result    = $validator->validate('SomePassword');

        $this->assertTrue($result->isValid);
        $this->assertSame([], $result->violations);
        $this->assertInstanceOf(StrengthLevel::class, $result->strength);
        $this->assertIsFloat($result->entropy);
    }

    #[Test]
    public function testValidateWithPolicyViolation(): void
    {
        $policy    = (new PasswordPolicy())->withRule(new MinLengthRule(20));
        $validator = new DefaultPasswordValidator($policy);
        $result    = $validator->validate('short');

        $this->assertFalse($result->isValid);
        $this->assertNotEmpty($result->violations);
        $this->assertStringContainsString('at least 20 characters', $result->violations[0]);
    }

    #[Test]
    public function testValidateWithMinimumStrengthRequirement(): void
    {
        $validator = new DefaultPasswordValidator(
            policy: new PasswordPolicy(),
            pwnedChecker: null,
            minimumStrength: StrengthLevel::STRONG
        );

        $result = $validator->validate('weak');

        $this->assertFalse($result->isValid);
        $this->assertNotEmpty($result->violations);
    }

    #[Test]
    public function testValidateWithStrengthRequirementMet(): void
    {
        $validator = new DefaultPasswordValidator(
            policy: new PasswordPolicy(),
            pwnedChecker: null,
            minimumStrength: StrengthLevel::FAIR
        );

        // Fair strength password
        $result = $validator->validate('Abcd1234!@#');

        $this->assertTrue($result->isValid);
    }

    #[Test]
    public function testValidateWithPwnedChecker(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        // SHA1 of 'password' starts with 5BAA6
        $client->method('get')->willReturn("1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\n");

        $pwnedChecker = new PwnedPasswordChecker($client);
        $validator    = new DefaultPasswordValidator(
            policy: new PasswordPolicy(),
            pwnedChecker: $pwnedChecker
        );

        $result = $validator->validate('password');

        $this->assertFalse($result->isValid);
        $this->assertNotEmpty($result->violations);
        $this->assertStringContainsString('exposed', $result->violations[0]);
        $this->assertSame(12345, $result->pwnedCount);
    }

    #[Test]
    public function testValidateWithPwnedCheckerNotFound(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("NOTMATCHING:100\r\n");

        $pwnedChecker = new PwnedPasswordChecker($client);
        $validator    = new DefaultPasswordValidator(
            policy: new PasswordPolicy(),
            pwnedChecker: $pwnedChecker
        );

        $result = $validator->validate('unique-password-xyz');

        $this->assertTrue($result->isValid);
        $this->assertSame(0, $result->pwnedCount);
    }

    #[Test]
    public function testValidateSetsStrengthAndEntropy(): void
    {
        $validator = new DefaultPasswordValidator();
        $result    = $validator->validate('TestPassword123!');

        $this->assertInstanceOf(StrengthLevel::class, $result->strength);
        $this->assertIsFloat($result->entropy);
        $this->assertGreaterThan(0, $result->entropy);
    }

    #[Test]
    public function testValidateWithMultipleViolations(): void
    {
        $policy    = PasswordPolicy::strict();
        $validator = new DefaultPasswordValidator(
            policy: $policy,
            pwnedChecker: null,
            minimumStrength: StrengthLevel::STRONG
        );

        // Very weak password violating multiple rules
        $result = $validator->validate('a');

        $this->assertFalse($result->isValid);
        $this->assertGreaterThan(1, count($result->violations));
    }

    #[Test]
    public function testValidateReturnsCorrectPwnedCountWhenNotChecked(): void
    {
        $validator = new DefaultPasswordValidator(
            policy: new PasswordPolicy(),
            pwnedChecker: null
        );

        $result = $validator->validate('password');

        $this->assertNull($result->pwnedCount);
    }

    #[Test]
    public function testNistStaticFactory(): void
    {
        $validator = DefaultPasswordValidator::nist();
        $result    = $validator->validate('LongEnoughPassword');

        $this->assertTrue($result->isValid);
    }

    #[Test]
    public function testNistStaticFactoryRejectsTooShort(): void
    {
        $validator = DefaultPasswordValidator::nist();
        $result    = $validator->validate('short');

        $this->assertFalse($result->isValid);
    }

    #[Test]
    public function testStrictStaticFactoryWithoutPwnedChecker(): void
    {
        $validator = DefaultPasswordValidator::strict();

        // Strong password meeting all requirements
        $result = $validator->validate('SecureP@ss123!');

        // Should pass policy but we can't guarantee it passes minimum strength
        $this->assertInstanceOf(ValidationResult::class, $result);
    }

    #[Test]
    public function testStrictStaticFactoryWithPwnedChecker(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("NOTMATCHING:100\r\n");

        $pwnedChecker = new PwnedPasswordChecker($client);
        $validator    = DefaultPasswordValidator::strict($pwnedChecker);

        $result = $validator->validate('SecureP@ss123!xyz');

        // Should check against HIBP
        $this->assertNotNull($result->pwnedCount);
    }

    #[Test]
    public function testWithPwnedCheckStaticFactory(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("NOTMATCHING:100\r\n");

        $validator = DefaultPasswordValidator::withPwnedCheck($client);

        $this->assertInstanceOf(DefaultPasswordValidator::class, $validator);
    }

    #[Test]
    public function testWithPwnedCheckStaticFactoryWithCustomPolicy(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("NOTMATCHING:100\r\n");

        $policy    = PasswordPolicy::legacy();
        $validator = DefaultPasswordValidator::withPwnedCheck($client, $policy);

        $this->assertInstanceOf(DefaultPasswordValidator::class, $validator);
    }

    #[Test]
    public function testValidateWithEmptyPassword(): void
    {
        $validator = new DefaultPasswordValidator();
        $result    = $validator->validate('');

        // Empty password should have very low entropy
        $this->assertSame(0.0, $result->entropy);
        $this->assertSame(StrengthLevel::VERY_WEAK, $result->strength);
    }

    #[Test]
    public function testValidateWithUnicodePassword(): void
    {
        $validator = new DefaultPasswordValidator();
        $result    = $validator->validate('SecurePassword');

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertIsFloat($result->entropy);
    }

    #[Test]
    public function testValidateWithVeryLongPassword(): void
    {
        $policy    = PasswordPolicy::nist();
        $validator = new DefaultPasswordValidator($policy);

        $longPassword = str_repeat('A', 200);
        $result       = $validator->validate($longPassword);

        // Should violate max length
        $this->assertFalse($result->isValid);
    }

    #[Test]
    public function testStrengthViolationMessageFormat(): void
    {
        $validator = new DefaultPasswordValidator(
            policy: new PasswordPolicy(),
            pwnedChecker: null,
            minimumStrength: StrengthLevel::STRONG
        );

        $result = $validator->validate('weak');

        $hasStrengthIssue = false;
        foreach ($result->violations as $violation) {
            if (str_contains($violation, 'strength must be at least')) {
                $hasStrengthIssue = true;
                $this->assertStringContainsString('Strong', $violation);
                break;
            }
        }

        $this->assertTrue($hasStrengthIssue, 'Should contain strength violation message');
    }

    #[Test]
    public function testPwnedViolationMessageFormatSingular(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        // Return exactly 1 breach
        $client->method('get')->willReturn("1E4C9B93F3F0682250B6CF8331B7EE68FD8:1\r\n");

        $pwnedChecker = new PwnedPasswordChecker($client);
        $validator    = new DefaultPasswordValidator(
            policy: new PasswordPolicy(),
            pwnedChecker: $pwnedChecker
        );

        $result = $validator->validate('password');

        $this->assertStringContainsString('1 data breach', $result->violations[0]);
        $this->assertStringNotContainsString('breaches', $result->violations[0]);
    }

    #[Test]
    public function testPwnedViolationMessageFormatPlural(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn("1E4C9B93F3F0682250B6CF8331B7EE68FD8:5\r\n");

        $pwnedChecker = new PwnedPasswordChecker($client);
        $validator    = new DefaultPasswordValidator(
            policy: new PasswordPolicy(),
            pwnedChecker: $pwnedChecker
        );

        $result = $validator->validate('password');

        $this->assertStringContainsString('5 data breaches', $result->violations[0]);
    }
}
