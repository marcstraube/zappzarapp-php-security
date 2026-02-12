<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\ReferrerPolicy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\ReferrerPolicy\ReferrerPolicyValue;

#[CoversClass(ReferrerPolicyValue::class)]
final class ReferrerPolicyValueTest extends TestCase
{
    public function testNoReferrerValue(): void
    {
        $this->assertSame('no-referrer', ReferrerPolicyValue::NO_REFERRER->value);
    }

    public function testNoReferrerWhenDowngradeValue(): void
    {
        $this->assertSame('no-referrer-when-downgrade', ReferrerPolicyValue::NO_REFERRER_WHEN_DOWNGRADE->value);
    }

    public function testOriginValue(): void
    {
        $this->assertSame('origin', ReferrerPolicyValue::ORIGIN->value);
    }

    public function testOriginWhenCrossOriginValue(): void
    {
        $this->assertSame('origin-when-cross-origin', ReferrerPolicyValue::ORIGIN_WHEN_CROSS_ORIGIN->value);
    }

    public function testSameOriginValue(): void
    {
        $this->assertSame('same-origin', ReferrerPolicyValue::SAME_ORIGIN->value);
    }

    public function testStrictOriginValue(): void
    {
        $this->assertSame('strict-origin', ReferrerPolicyValue::STRICT_ORIGIN->value);
    }

    public function testStrictOriginWhenCrossOriginValue(): void
    {
        $this->assertSame('strict-origin-when-cross-origin', ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN->value);
    }

    public function testUnsafeUrlValue(): void
    {
        $this->assertSame('unsafe-url', ReferrerPolicyValue::UNSAFE_URL->value);
    }

    public function testHeaderValueReturnsEnumValue(): void
    {
        $this->assertSame('no-referrer', ReferrerPolicyValue::NO_REFERRER->headerValue());
        $this->assertSame('strict-origin-when-cross-origin', ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN->headerValue());
    }

    public function testAllCasesExist(): void
    {
        $cases = ReferrerPolicyValue::cases();

        $this->assertCount(8, $cases);
    }
}
