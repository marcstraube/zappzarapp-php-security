<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\SignedUrl\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\SignedUrl\Exception\InvalidContextException;

#[CoversClass(InvalidContextException::class)]
final class InvalidContextExceptionTest extends TestCase
{
    #[Test]
    public function testContainsControlCharactersFactoryMethod(): void
    {
        $exception = InvalidContextException::containsControlCharacters();

        $this->assertSame('Context value must not contain control characters', $exception->getMessage());
    }
}
