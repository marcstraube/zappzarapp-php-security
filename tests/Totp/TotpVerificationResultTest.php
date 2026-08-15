<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Totp\TotpVerificationResult;

#[CoversClass(TotpVerificationResult::class)]
final class TotpVerificationResultTest extends TestCase
{
    #[Test]
    public function testValidCarriesMatchedTimeStep(): void
    {
        $result = TotpVerificationResult::valid(37037037);

        $this->assertTrue($result->valid);
        $this->assertSame(37037037, $result->matchedTimeStep);
    }

    #[Test]
    public function testInvalidHasNoMatchedTimeStep(): void
    {
        $result = TotpVerificationResult::invalid();

        $this->assertFalse($result->valid);
        $this->assertNull($result->matchedTimeStep);
    }
}
