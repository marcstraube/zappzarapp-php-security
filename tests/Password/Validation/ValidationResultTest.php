<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Validation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Strength\StrengthLevel;
use Zappzarapp\Security\Password\Validation\ValidationResult;

#[CoversClass(ValidationResult::class)]
final class ValidationResultTest extends TestCase
{
    public function testConstructorWithAllParameters(): void
    {
        $result = new ValidationResult(
            isValid: true,
            violations: ['test violation'],
            strength: StrengthLevel::STRONG,
            entropy: 65.5,
            pwnedCount: 0
        );

        $this->assertTrue($result->isValid);
        $this->assertSame(['test violation'], $result->violations);
        $this->assertSame(StrengthLevel::STRONG, $result->strength);
        $this->assertSame(65.5, $result->entropy);
        $this->assertSame(0, $result->pwnedCount);
    }

    public function testConstructorWithDefaultParameters(): void
    {
        $result = new ValidationResult(isValid: false);

        $this->assertFalse($result->isValid);
        $this->assertSame([], $result->violations);
        $this->assertNull($result->strength);
        $this->assertNull($result->entropy);
        $this->assertNull($result->pwnedCount);
    }

    public function testValidFactoryMethod(): void
    {
        $result = ValidationResult::valid();

        $this->assertTrue($result->isValid);
        $this->assertSame([], $result->violations);
        $this->assertNull($result->strength);
        $this->assertNull($result->entropy);
        $this->assertNull($result->pwnedCount);
    }

    public function testValidFactoryMethodWithAllParameters(): void
    {
        $result = ValidationResult::valid(
            strength: StrengthLevel::VERY_STRONG,
            entropy: 128.0,
            pwnedCount: 0
        );

        $this->assertTrue($result->isValid);
        $this->assertSame([], $result->violations);
        $this->assertSame(StrengthLevel::VERY_STRONG, $result->strength);
        $this->assertSame(128.0, $result->entropy);
        $this->assertSame(0, $result->pwnedCount);
    }

    public function testInvalidFactoryMethod(): void
    {
        $violations = ['Too short', 'Missing uppercase'];
        $result     = ValidationResult::invalid($violations);

        $this->assertFalse($result->isValid);
        $this->assertSame($violations, $result->violations);
        $this->assertNull($result->strength);
        $this->assertNull($result->entropy);
        $this->assertNull($result->pwnedCount);
    }

    public function testInvalidFactoryMethodWithAllParameters(): void
    {
        $violations = ['Password found in breach'];
        $result     = ValidationResult::invalid(
            violations: $violations,
            strength: StrengthLevel::FAIR,
            entropy: 45.0,
            pwnedCount: 500
        );

        $this->assertFalse($result->isValid);
        $this->assertSame($violations, $result->violations);
        $this->assertSame(StrengthLevel::FAIR, $result->strength);
        $this->assertSame(45.0, $result->entropy);
        $this->assertSame(500, $result->pwnedCount);
    }

    public function testPassedReturnsTrueForValidResult(): void
    {
        $result = ValidationResult::valid();

        $this->assertTrue($result->passed());
    }

    public function testPassedReturnsFalseForInvalidResult(): void
    {
        $result = ValidationResult::invalid(['error']);

        $this->assertFalse($result->passed());
    }

    public function testFailedReturnsFalseForValidResult(): void
    {
        $result = ValidationResult::valid();

        $this->assertFalse($result->failed());
    }

    public function testFailedReturnsTrueForInvalidResult(): void
    {
        $result = ValidationResult::invalid(['error']);

        $this->assertTrue($result->failed());
    }

    public function testIsPwnedReturnsTrueWhenPwnedCountGreaterThanZero(): void
    {
        $result = new ValidationResult(
            isValid: false,
            violations: [],
            pwnedCount: 100
        );

        $this->assertTrue($result->isPwned());
    }

    public function testIsPwnedReturnsFalseWhenPwnedCountIsZero(): void
    {
        $result = new ValidationResult(
            isValid: true,
            violations: [],
            pwnedCount: 0
        );

        $this->assertFalse($result->isPwned());
    }

    public function testIsPwnedReturnsFalseWhenPwnedCountIsNull(): void
    {
        $result = new ValidationResult(
            isValid: true,
            violations: [],
            pwnedCount: null
        );

        $this->assertFalse($result->isPwned());
    }

    public function testPassedAndFailedAreOpposites(): void
    {
        $valid   = ValidationResult::valid();
        $invalid = ValidationResult::invalid(['error']);

        $this->assertSame($valid->passed(), !$valid->failed());
        $this->assertSame($invalid->passed(), !$invalid->failed());
    }

    public function testIsValidPublicProperty(): void
    {
        $valid   = ValidationResult::valid();
        $invalid = ValidationResult::invalid(['error']);

        $this->assertTrue($valid->isValid);
        $this->assertFalse($invalid->isValid);
    }

    public function testViolationsAreAccessible(): void
    {
        $violations = ['Error 1', 'Error 2', 'Error 3'];
        $result     = ValidationResult::invalid($violations);

        $this->assertSame($violations, $result->violations);
        $this->assertCount(3, $result->violations);
    }

    public function testEmptyViolationsForValidResult(): void
    {
        $result = ValidationResult::valid();

        $this->assertSame([], $result->violations);
        $this->assertEmpty($result->violations);
    }

    public function testAllStrengthLevels(): void
    {
        foreach (StrengthLevel::cases() as $level) {
            $result = ValidationResult::valid(strength: $level);

            $this->assertSame($level, $result->strength);
        }
    }

    public function testEntropyPrecision(): void
    {
        $entropy = 45.123456789;
        $result  = ValidationResult::valid(entropy: $entropy);

        $this->assertSame($entropy, $result->entropy);
    }

    public function testLargePwnedCount(): void
    {
        $largeCount = 10000000;
        $result     = new ValidationResult(
            isValid: false,
            violations: ['Breached'],
            pwnedCount: $largeCount
        );

        $this->assertSame($largeCount, $result->pwnedCount);
        $this->assertTrue($result->isPwned());
    }
}
