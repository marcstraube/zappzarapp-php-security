<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\ReferrerPolicy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\ReferrerPolicy\ReferrerPolicyValue;

#[CoversClass(ReferrerPolicyValue::class)]
final class ReferrerPolicyValueTest extends TestCase
{
    #[Test]
    public function testNoReferrerValue(): void
    {
        $this->assertSame('no-referrer', ReferrerPolicyValue::NO_REFERRER->value);
    }

    #[Test]
    public function testNoReferrerWhenDowngradeValue(): void
    {
        $this->assertSame('no-referrer-when-downgrade', ReferrerPolicyValue::NO_REFERRER_WHEN_DOWNGRADE->value);
    }

    #[Test]
    public function testOriginValue(): void
    {
        $this->assertSame('origin', ReferrerPolicyValue::ORIGIN->value);
    }

    #[Test]
    public function testOriginWhenCrossOriginValue(): void
    {
        $this->assertSame('origin-when-cross-origin', ReferrerPolicyValue::ORIGIN_WHEN_CROSS_ORIGIN->value);
    }

    #[Test]
    public function testSameOriginValue(): void
    {
        $this->assertSame('same-origin', ReferrerPolicyValue::SAME_ORIGIN->value);
    }

    #[Test]
    public function testStrictOriginValue(): void
    {
        $this->assertSame('strict-origin', ReferrerPolicyValue::STRICT_ORIGIN->value);
    }

    #[Test]
    public function testStrictOriginWhenCrossOriginValue(): void
    {
        $this->assertSame('strict-origin-when-cross-origin', ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN->value);
    }

    #[Test]
    public function testUnsafeUrlValue(): void
    {
        $this->assertSame('unsafe-url', ReferrerPolicyValue::UNSAFE_URL->value);
    }

    #[Test]
    public function testHeaderValueReturnsEnumValue(): void
    {
        $this->assertSame('no-referrer', ReferrerPolicyValue::NO_REFERRER->headerValue());
        $this->assertSame('strict-origin-when-cross-origin', ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN->headerValue());
    }

    #[Test]
    public function testAllCasesExist(): void
    {
        $cases = ReferrerPolicyValue::cases();

        $this->assertCount(8, $cases);
    }
}
