<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Cookie\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieOptionsException;

#[CoversClass(InvalidCookieOptionsException::class)]
final class InvalidCookieOptionsExceptionTest extends TestCase
{
    #[Test]
    public function testExtendsInvalidArgumentException(): void
    {
        $exception = InvalidCookieOptionsException::invalidPath('/test');

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies inheritance */
        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
    }

    // --- invalidPath ---

    #[Test]
    public function testInvalidPathContainsPath(): void
    {
        $exception = InvalidCookieOptionsException::invalidPath('/evil;path');

        $this->assertStringContainsString('/evil;path', $exception->getMessage());
        $this->assertStringContainsString('invalid characters', $exception->getMessage());
    }

    #[Test]
    public function testInvalidPathTruncatesLongPaths(): void
    {
        $longPath  = str_repeat('a', 100);
        $exception = InvalidCookieOptionsException::invalidPath($longPath);

        // Should be truncated with ...
        $this->assertStringContainsString('...', $exception->getMessage());
        $this->assertStringNotContainsString(str_repeat('a', 100), $exception->getMessage());
    }

    // --- invalidDomain ---

    #[Test]
    public function testInvalidDomainContainsDomain(): void
    {
        $exception = InvalidCookieOptionsException::invalidDomain("evil\r\n.com");

        $this->assertStringContainsString('invalid characters', $exception->getMessage());
    }

    #[Test]
    public function testInvalidDomainTruncatesLongDomains(): void
    {
        $longDomain = str_repeat('a', 100) . '.com';
        $exception  = InvalidCookieOptionsException::invalidDomain($longDomain);

        // Should be truncated with ...
        $this->assertStringContainsString('...', $exception->getMessage());
    }

    // --- sameSiteNoneRequiresSecure ---

    #[Test]
    public function testSameSiteNoneRequiresSecureMessage(): void
    {
        $exception = InvalidCookieOptionsException::sameSiteNoneRequiresSecure();

        $this->assertStringContainsString('SameSite=None', $exception->getMessage());
        $this->assertStringContainsString('Secure', $exception->getMessage());
        $this->assertStringContainsString('withSameSiteNone()', $exception->getMessage());
    }
}
