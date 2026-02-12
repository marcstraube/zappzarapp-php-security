<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sri\CrossOrigin;

#[CoversClass(CrossOrigin::class)]
final class CrossOriginTest extends TestCase
{
    public function testAnonymousValue(): void
    {
        $this->assertSame('anonymous', CrossOrigin::ANONYMOUS->value);
    }

    public function testUseCredentialsValue(): void
    {
        $this->assertSame('use-credentials', CrossOrigin::USE_CREDENTIALS->value);
    }

    public function testAnonymousAttributeValue(): void
    {
        $this->assertSame('anonymous', CrossOrigin::ANONYMOUS->attributeValue());
    }

    public function testUseCredentialsAttributeValue(): void
    {
        $this->assertSame('use-credentials', CrossOrigin::USE_CREDENTIALS->attributeValue());
    }

    public function testAllCasesExist(): void
    {
        $cases = CrossOrigin::cases();

        $this->assertCount(2, $cases);
        $this->assertContains(CrossOrigin::ANONYMOUS, $cases);
        $this->assertContains(CrossOrigin::USE_CREDENTIALS, $cases);
    }
}
