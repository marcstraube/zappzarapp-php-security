<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\XFrameOptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\XFrameOptions\XFrameOptionsValue;

#[CoversClass(XFrameOptionsValue::class)]
final class XFrameOptionsValueTest extends TestCase
{
    public function testDenyValue(): void
    {
        $this->assertSame('DENY', XFrameOptionsValue::DENY->value);
    }

    public function testSameOriginValue(): void
    {
        $this->assertSame('SAMEORIGIN', XFrameOptionsValue::SAMEORIGIN->value);
    }

    public function testHeaderValueDeny(): void
    {
        $this->assertSame('DENY', XFrameOptionsValue::DENY->headerValue());
    }

    public function testHeaderValueSameOrigin(): void
    {
        $this->assertSame('SAMEORIGIN', XFrameOptionsValue::SAMEORIGIN->headerValue());
    }

    public function testAllCasesExist(): void
    {
        $cases = XFrameOptionsValue::cases();

        $this->assertCount(2, $cases);
        $this->assertContains(XFrameOptionsValue::DENY, $cases);
        $this->assertContains(XFrameOptionsValue::SAMEORIGIN, $cases);
    }
}
