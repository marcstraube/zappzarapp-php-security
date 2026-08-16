<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\SignedUrl\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\SignedUrl\Exception\InvalidSignatureException;

#[CoversClass(InvalidSignatureException::class)]
final class InvalidSignatureExceptionTest extends TestCase
{
    #[Test]
    public function testMismatchFactoryMethod(): void
    {
        $exception = InvalidSignatureException::mismatch();

        $this->assertSame('Signed URL signature does not match the URL contents', $exception->getMessage());
    }
}
