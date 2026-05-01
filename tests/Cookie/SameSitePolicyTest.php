<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Cookie;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cookie\SameSitePolicy;

#[CoversClass(SameSitePolicy::class)]
final class SameSitePolicyTest extends TestCase
{
    #[Test]
    public function testNoneValue(): void
    {
        $this->assertSame('None', SameSitePolicy::NONE->value);
    }

    #[Test]
    public function testLaxValue(): void
    {
        $this->assertSame('Lax', SameSitePolicy::LAX->value);
    }

    #[Test]
    public function testStrictValue(): void
    {
        $this->assertSame('Strict', SameSitePolicy::STRICT->value);
    }

    #[Test]
    public function testNoneAttributeValue(): void
    {
        $this->assertSame('None', SameSitePolicy::NONE->attributeValue());
    }

    #[Test]
    public function testLaxAttributeValue(): void
    {
        $this->assertSame('Lax', SameSitePolicy::LAX->attributeValue());
    }

    #[Test]
    public function testStrictAttributeValue(): void
    {
        $this->assertSame('Strict', SameSitePolicy::STRICT->attributeValue());
    }

    /**
     * @return array<string, array{SameSitePolicy, string}>
     */
    public static function attributeValueProvider(): array
    {
        return [
            'none'   => [SameSitePolicy::NONE, 'None'],
            'lax'    => [SameSitePolicy::LAX, 'Lax'],
            'strict' => [SameSitePolicy::STRICT, 'Strict'],
        ];
    }

    #[DataProvider('attributeValueProvider')]
    #[Test]
    public function testAttributeValueMatchesEnumValue(SameSitePolicy $policy, string $expected): void
    {
        $this->assertSame($expected, $policy->attributeValue());
        $this->assertSame($policy->value, $policy->attributeValue());
    }

    #[Test]
    public function testAllCasesExist(): void
    {
        $cases = SameSitePolicy::cases();

        $this->assertCount(3, $cases);
        $this->assertContains(SameSitePolicy::NONE, $cases);
        $this->assertContains(SameSitePolicy::LAX, $cases);
        $this->assertContains(SameSitePolicy::STRICT, $cases);
    }
}
