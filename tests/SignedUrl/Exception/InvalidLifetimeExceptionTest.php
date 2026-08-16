<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\SignedUrl\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\SignedUrl\Exception\InvalidLifetimeException;

#[CoversClass(InvalidLifetimeException::class)]
final class InvalidLifetimeExceptionTest extends TestCase
{
    #[Test]
    public function testNonPositiveFactoryMethod(): void
    {
        $exception = InvalidLifetimeException::nonPositive(-60);

        $this->assertSame(
            'Signed URL lifetime must be a positive number of seconds, got -60',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testExceedsMaximumFactoryMethod(): void
    {
        $exception = InvalidLifetimeException::exceedsMaximum(3_153_600_001, 3_153_600_000);

        $this->assertSame(
            'Signed URL lifetime must not exceed 3153600000 seconds (100 years), got 3153600001',
            $exception->getMessage()
        );
    }
}
