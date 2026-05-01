<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sri\HashAlgorithm;

#[CoversClass(HashAlgorithm::class)]
final class HashAlgorithmTest extends TestCase
{
    #[Test]
    public function testSha384Value(): void
    {
        $this->assertSame('sha384', HashAlgorithm::SHA384->value);
    }

    #[Test]
    public function testSha512Value(): void
    {
        $this->assertSame('sha512', HashAlgorithm::SHA512->value);
    }

    #[Test]
    public function testSha384Prefix(): void
    {
        $this->assertSame('sha384', HashAlgorithm::SHA384->prefix());
    }

    #[Test]
    public function testSha512Prefix(): void
    {
        $this->assertSame('sha512', HashAlgorithm::SHA512->prefix());
    }

    #[Test]
    public function testSha384ByteLength(): void
    {
        $this->assertSame(48, HashAlgorithm::SHA384->byteLength());
    }

    #[Test]
    public function testSha512ByteLength(): void
    {
        $this->assertSame(64, HashAlgorithm::SHA512->byteLength());
    }

    #[Test]
    public function testSha384Base64Length(): void
    {
        // base64Length = ceil(byteLength * 4 / 3) = ceil(48 * 4 / 3) = 64
        $this->assertSame(64, HashAlgorithm::SHA384->base64Length());
    }

    #[Test]
    public function testSha512Base64Length(): void
    {
        // base64Length = ceil(byteLength * 4 / 3) = ceil(64 * 4 / 3) = 86
        $this->assertSame(86, HashAlgorithm::SHA512->base64Length());
    }

    #[Test]
    public function testRecommended(): void
    {
        $this->assertSame(HashAlgorithm::SHA384, HashAlgorithm::recommended());
    }

    #[Test]
    public function testFromStringValid(): void
    {
        $this->assertSame(HashAlgorithm::SHA384, HashAlgorithm::fromString('sha384'));
        $this->assertSame(HashAlgorithm::SHA512, HashAlgorithm::fromString('sha512'));
    }

    #[Test]
    public function testFromStringCaseInsensitive(): void
    {
        $this->assertSame(HashAlgorithm::SHA384, HashAlgorithm::fromString('SHA384'));
        $this->assertSame(HashAlgorithm::SHA512, HashAlgorithm::fromString('SHA512'));
    }

    #[Test]
    public function testFromStringWithHyphenatedFormat(): void
    {
        $this->assertSame(HashAlgorithm::SHA384, HashAlgorithm::fromString('sha-384'));
        $this->assertSame(HashAlgorithm::SHA512, HashAlgorithm::fromString('sha-512'));
    }

    #[Test]
    public function testFromStringWithHyphenatedFormatCaseInsensitive(): void
    {
        $this->assertSame(HashAlgorithm::SHA384, HashAlgorithm::fromString('SHA-384'));
        $this->assertSame(HashAlgorithm::SHA512, HashAlgorithm::fromString('SHA-512'));
    }

    #[Test]
    public function testFromStringInvalid(): void
    {
        $this->assertNull(HashAlgorithm::fromString('md5'));
        $this->assertNull(HashAlgorithm::fromString('sha1'));
        $this->assertNull(HashAlgorithm::fromString('sha256')); // SHA-256 not supported
        $this->assertNull(HashAlgorithm::fromString('invalid'));
    }

    #[Test]
    public function testAllCasesExist(): void
    {
        $cases = HashAlgorithm::cases();

        $this->assertCount(2, $cases);
        $this->assertContains(HashAlgorithm::SHA384, $cases);
        $this->assertContains(HashAlgorithm::SHA512, $cases);
    }
}
