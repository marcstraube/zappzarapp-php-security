<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\Coop;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Coop\CoopValue;

#[CoversClass(CoopValue::class)]
final class CoopValueTest extends TestCase
{
    public function testUnsafeNoneValue(): void
    {
        $this->assertSame('unsafe-none', CoopValue::UNSAFE_NONE->value);
    }

    public function testSameOriginAllowPopupsValue(): void
    {
        $this->assertSame('same-origin-allow-popups', CoopValue::SAME_ORIGIN_ALLOW_POPUPS->value);
    }

    public function testSameOriginValue(): void
    {
        $this->assertSame('same-origin', CoopValue::SAME_ORIGIN->value);
    }

    public function testHeaderValueUnsafeNone(): void
    {
        $this->assertSame('unsafe-none', CoopValue::UNSAFE_NONE->headerValue());
    }

    public function testHeaderValueSameOriginAllowPopups(): void
    {
        $this->assertSame('same-origin-allow-popups', CoopValue::SAME_ORIGIN_ALLOW_POPUPS->headerValue());
    }

    public function testHeaderValueSameOrigin(): void
    {
        $this->assertSame('same-origin', CoopValue::SAME_ORIGIN->headerValue());
    }

    public function testAllCasesExist(): void
    {
        $cases = CoopValue::cases();

        $this->assertCount(3, $cases);
        $this->assertContains(CoopValue::UNSAFE_NONE, $cases);
        $this->assertContains(CoopValue::SAME_ORIGIN_ALLOW_POPUPS, $cases);
        $this->assertContains(CoopValue::SAME_ORIGIN, $cases);
    }
}
