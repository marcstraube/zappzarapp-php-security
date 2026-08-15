<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Totp\TotpAlgorithm;

#[CoversClass(TotpAlgorithm::class)]
final class TotpAlgorithmTest extends TestCase
{
    #[Test]
    public function testHashNames(): void
    {
        $this->assertSame('sha1', TotpAlgorithm::Sha1->hashName());
        $this->assertSame('sha256', TotpAlgorithm::Sha256->hashName());
        $this->assertSame('sha512', TotpAlgorithm::Sha512->hashName());
    }

    #[Test]
    public function testRecommendedSecretBytesMatchHashOutputSize(): void
    {
        $this->assertSame(20, TotpAlgorithm::Sha1->recommendedSecretBytes());
        $this->assertSame(32, TotpAlgorithm::Sha256->recommendedSecretBytes());
        $this->assertSame(64, TotpAlgorithm::Sha512->recommendedSecretBytes());
    }

    #[Test]
    public function testUriValuesAreUppercase(): void
    {
        $this->assertSame('SHA1', TotpAlgorithm::Sha1->value);
        $this->assertSame('SHA256', TotpAlgorithm::Sha256->value);
        $this->assertSame('SHA512', TotpAlgorithm::Sha512->value);
    }
}
