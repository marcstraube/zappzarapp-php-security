<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\SignedUrl\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\SignedUrl\Exception\UrlExpiredException;

#[CoversClass(UrlExpiredException::class)]
final class UrlExpiredExceptionTest extends TestCase
{
    #[Test]
    public function testExpiredAtFactoryMethod(): void
    {
        $exception = UrlExpiredException::expiredAt(1_800_000_000, 1_800_003_600);

        $this->assertSame(
            'Signed URL expired at 1800000000 (now: 1800003600)',
            $exception->getMessage()
        );
    }
}
