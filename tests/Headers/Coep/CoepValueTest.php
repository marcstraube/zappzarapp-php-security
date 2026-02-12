<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\Coep;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Coep\CoepValue;

#[CoversClass(CoepValue::class)]
final class CoepValueTest extends TestCase
{
    public function testUnsafeNoneValue(): void
    {
        $this->assertSame('unsafe-none', CoepValue::UNSAFE_NONE->value);
    }

    public function testRequireCorpValue(): void
    {
        $this->assertSame('require-corp', CoepValue::REQUIRE_CORP->value);
    }

    public function testCredentiallessValue(): void
    {
        $this->assertSame('credentialless', CoepValue::CREDENTIALLESS->value);
    }

    public function testHeaderValueUnsafeNone(): void
    {
        $this->assertSame('unsafe-none', CoepValue::UNSAFE_NONE->headerValue());
    }

    public function testHeaderValueRequireCorp(): void
    {
        $this->assertSame('require-corp', CoepValue::REQUIRE_CORP->headerValue());
    }

    public function testHeaderValueCredentialless(): void
    {
        $this->assertSame('credentialless', CoepValue::CREDENTIALLESS->headerValue());
    }

    public function testAllCasesExist(): void
    {
        $cases = CoepValue::cases();

        $this->assertCount(3, $cases);
        $this->assertContains(CoepValue::UNSAFE_NONE, $cases);
        $this->assertContains(CoepValue::REQUIRE_CORP, $cases);
        $this->assertContains(CoepValue::CREDENTIALLESS, $cases);
    }
}
