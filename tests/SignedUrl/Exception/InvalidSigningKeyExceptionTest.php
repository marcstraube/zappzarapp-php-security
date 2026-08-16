<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\SignedUrl\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\SignedUrl\Exception\InvalidSigningKeyException;

#[CoversClass(InvalidSigningKeyException::class)]
final class InvalidSigningKeyExceptionTest extends TestCase
{
    #[Test]
    public function testTooShortFactoryMethod(): void
    {
        $exception = InvalidSigningKeyException::tooShort(32, 16);

        $this->assertSame('Signing key must be at least 32 bytes, got 16 bytes', $exception->getMessage());
    }

    #[Test]
    public function testInvalidEncodingFactoryMethod(): void
    {
        $exception = InvalidSigningKeyException::invalidEncoding();

        $this->assertSame('Signing key material is not valid base64', $exception->getMessage());
    }
}
