<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\Corp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Corp\CorpValue;

#[CoversClass(CorpValue::class)]
final class CorpValueTest extends TestCase
{
    #[Test]
    public function testSameOriginValue(): void
    {
        $this->assertSame('same-origin', CorpValue::SAME_ORIGIN->value);
    }

    #[Test]
    public function testSameSiteValue(): void
    {
        $this->assertSame('same-site', CorpValue::SAME_SITE->value);
    }

    #[Test]
    public function testCrossOriginValue(): void
    {
        $this->assertSame('cross-origin', CorpValue::CROSS_ORIGIN->value);
    }

    #[Test]
    public function testHeaderValueSameOrigin(): void
    {
        $this->assertSame('same-origin', CorpValue::SAME_ORIGIN->headerValue());
    }

    #[Test]
    public function testHeaderValueSameSite(): void
    {
        $this->assertSame('same-site', CorpValue::SAME_SITE->headerValue());
    }

    #[Test]
    public function testHeaderValueCrossOrigin(): void
    {
        $this->assertSame('cross-origin', CorpValue::CROSS_ORIGIN->headerValue());
    }

    #[Test]
    public function testAllCasesExist(): void
    {
        $cases = CorpValue::cases();

        $this->assertCount(3, $cases);
        $this->assertContains(CorpValue::SAME_ORIGIN, $cases);
        $this->assertContains(CorpValue::SAME_SITE, $cases);
        $this->assertContains(CorpValue::CROSS_ORIGIN, $cases);
    }
}
