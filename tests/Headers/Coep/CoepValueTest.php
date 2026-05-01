<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\Coep;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Coep\CoepValue;

#[CoversClass(CoepValue::class)]
final class CoepValueTest extends TestCase
{
    #[Test]
    public function testUnsafeNoneValue(): void
    {
        $this->assertSame('unsafe-none', CoepValue::UNSAFE_NONE->value);
    }

    #[Test]
    public function testRequireCorpValue(): void
    {
        $this->assertSame('require-corp', CoepValue::REQUIRE_CORP->value);
    }

    #[Test]
    public function testCredentiallessValue(): void
    {
        $this->assertSame('credentialless', CoepValue::CREDENTIALLESS->value);
    }

    #[Test]
    public function testHeaderValueUnsafeNone(): void
    {
        $this->assertSame('unsafe-none', CoepValue::UNSAFE_NONE->headerValue());
    }

    #[Test]
    public function testHeaderValueRequireCorp(): void
    {
        $this->assertSame('require-corp', CoepValue::REQUIRE_CORP->headerValue());
    }

    #[Test]
    public function testHeaderValueCredentialless(): void
    {
        $this->assertSame('credentialless', CoepValue::CREDENTIALLESS->headerValue());
    }

    #[Test]
    public function testAllCasesExist(): void
    {
        $cases = CoepValue::cases();

        $this->assertCount(3, $cases);
        $this->assertContains(CoepValue::UNSAFE_NONE, $cases);
        $this->assertContains(CoepValue::REQUIRE_CORP, $cases);
        $this->assertContains(CoepValue::CREDENTIALLESS, $cases);
    }
}
