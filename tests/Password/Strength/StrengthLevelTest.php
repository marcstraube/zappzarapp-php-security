<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Strength;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Strength\StrengthLevel;

#[CoversClass(StrengthLevel::class)]
final class StrengthLevelTest extends TestCase
{
    #[Test]
    public function testAllCasesExist(): void
    {
        $cases = StrengthLevel::cases();

        $this->assertCount(5, $cases);
        $this->assertContains(StrengthLevel::VERY_WEAK, $cases);
        $this->assertContains(StrengthLevel::WEAK, $cases);
        $this->assertContains(StrengthLevel::FAIR, $cases);
        $this->assertContains(StrengthLevel::STRONG, $cases);
        $this->assertContains(StrengthLevel::VERY_STRONG, $cases);
    }

    #[Test]
    public function testVeryWeakValue(): void
    {
        $this->assertSame('very_weak', StrengthLevel::VERY_WEAK->value);
    }

    #[Test]
    public function testWeakValue(): void
    {
        $this->assertSame('weak', StrengthLevel::WEAK->value);
    }

    #[Test]
    public function testFairValue(): void
    {
        $this->assertSame('fair', StrengthLevel::FAIR->value);
    }

    #[Test]
    public function testStrongValue(): void
    {
        $this->assertSame('strong', StrengthLevel::STRONG->value);
    }

    #[Test]
    public function testVeryStrongValue(): void
    {
        $this->assertSame('very_strong', StrengthLevel::VERY_STRONG->value);
    }

    #[Test]
    public function testLabelVeryWeak(): void
    {
        $this->assertSame('Very Weak', StrengthLevel::VERY_WEAK->label());
    }

    #[Test]
    public function testLabelWeak(): void
    {
        $this->assertSame('Weak', StrengthLevel::WEAK->label());
    }

    #[Test]
    public function testLabelFair(): void
    {
        $this->assertSame('Fair', StrengthLevel::FAIR->label());
    }

    #[Test]
    public function testLabelStrong(): void
    {
        $this->assertSame('Strong', StrengthLevel::STRONG->label());
    }

    #[Test]
    public function testLabelVeryStrong(): void
    {
        $this->assertSame('Very Strong', StrengthLevel::VERY_STRONG->label());
    }

    #[Test]
    public function testScoreVeryWeak(): void
    {
        $this->assertSame(0, StrengthLevel::VERY_WEAK->score());
    }

    #[Test]
    public function testScoreWeak(): void
    {
        $this->assertSame(1, StrengthLevel::WEAK->score());
    }

    #[Test]
    public function testScoreFair(): void
    {
        $this->assertSame(2, StrengthLevel::FAIR->score());
    }

    #[Test]
    public function testScoreStrong(): void
    {
        $this->assertSame(3, StrengthLevel::STRONG->score());
    }

    #[Test]
    public function testScoreVeryStrong(): void
    {
        $this->assertSame(4, StrengthLevel::VERY_STRONG->score());
    }

    #[Test]
    public function testMeetsMinimumWhenExactlyAtMinimum(): void
    {
        $this->assertTrue(StrengthLevel::FAIR->meetsMinimum(StrengthLevel::FAIR));
        $this->assertTrue(StrengthLevel::STRONG->meetsMinimum(StrengthLevel::STRONG));
        $this->assertTrue(StrengthLevel::VERY_WEAK->meetsMinimum(StrengthLevel::VERY_WEAK));
    }

    #[Test]
    public function testMeetsMinimumWhenAboveMinimum(): void
    {
        $this->assertTrue(StrengthLevel::VERY_STRONG->meetsMinimum(StrengthLevel::STRONG));
        $this->assertTrue(StrengthLevel::STRONG->meetsMinimum(StrengthLevel::FAIR));
        $this->assertTrue(StrengthLevel::FAIR->meetsMinimum(StrengthLevel::WEAK));
        $this->assertTrue(StrengthLevel::WEAK->meetsMinimum(StrengthLevel::VERY_WEAK));
    }

    #[Test]
    public function testMeetsMinimumWhenBelowMinimum(): void
    {
        $this->assertFalse(StrengthLevel::VERY_WEAK->meetsMinimum(StrengthLevel::WEAK));
        $this->assertFalse(StrengthLevel::WEAK->meetsMinimum(StrengthLevel::FAIR));
        $this->assertFalse(StrengthLevel::FAIR->meetsMinimum(StrengthLevel::STRONG));
        $this->assertFalse(StrengthLevel::STRONG->meetsMinimum(StrengthLevel::VERY_STRONG));
    }

    #[Test]
    public function testMeetsMinimumVeryWeakMeetsAllMinimums(): void
    {
        // VERY_WEAK only meets VERY_WEAK requirement
        $this->assertTrue(StrengthLevel::VERY_WEAK->meetsMinimum(StrengthLevel::VERY_WEAK));
        $this->assertFalse(StrengthLevel::VERY_WEAK->meetsMinimum(StrengthLevel::WEAK));
        $this->assertFalse(StrengthLevel::VERY_WEAK->meetsMinimum(StrengthLevel::FAIR));
        $this->assertFalse(StrengthLevel::VERY_WEAK->meetsMinimum(StrengthLevel::STRONG));
        $this->assertFalse(StrengthLevel::VERY_WEAK->meetsMinimum(StrengthLevel::VERY_STRONG));
    }

    #[Test]
    public function testMeetsMinimumVeryStrongMeetsAllMinimums(): void
    {
        // VERY_STRONG meets all minimum requirements
        $this->assertTrue(StrengthLevel::VERY_STRONG->meetsMinimum(StrengthLevel::VERY_WEAK));
        $this->assertTrue(StrengthLevel::VERY_STRONG->meetsMinimum(StrengthLevel::WEAK));
        $this->assertTrue(StrengthLevel::VERY_STRONG->meetsMinimum(StrengthLevel::FAIR));
        $this->assertTrue(StrengthLevel::VERY_STRONG->meetsMinimum(StrengthLevel::STRONG));
        $this->assertTrue(StrengthLevel::VERY_STRONG->meetsMinimum(StrengthLevel::VERY_STRONG));
    }
}
