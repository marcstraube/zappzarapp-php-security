<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\Corp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Corp\CorpValue;

#[CoversClass(CorpValue::class)]
final class CorpValueTest extends TestCase
{
    public function testSameOriginValue(): void
    {
        $this->assertSame('same-origin', CorpValue::SAME_ORIGIN->value);
    }

    public function testSameSiteValue(): void
    {
        $this->assertSame('same-site', CorpValue::SAME_SITE->value);
    }

    public function testCrossOriginValue(): void
    {
        $this->assertSame('cross-origin', CorpValue::CROSS_ORIGIN->value);
    }

    public function testHeaderValueSameOrigin(): void
    {
        $this->assertSame('same-origin', CorpValue::SAME_ORIGIN->headerValue());
    }

    public function testHeaderValueSameSite(): void
    {
        $this->assertSame('same-site', CorpValue::SAME_SITE->headerValue());
    }

    public function testHeaderValueCrossOrigin(): void
    {
        $this->assertSame('cross-origin', CorpValue::CROSS_ORIGIN->headerValue());
    }

    public function testAllCasesExist(): void
    {
        $cases = CorpValue::cases();

        $this->assertCount(3, $cases);
        $this->assertContains(CorpValue::SAME_ORIGIN, $cases);
        $this->assertContains(CorpValue::SAME_SITE, $cases);
        $this->assertContains(CorpValue::CROSS_ORIGIN, $cases);
    }
}
