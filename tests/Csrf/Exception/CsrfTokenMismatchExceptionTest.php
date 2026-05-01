<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;

#[CoversClass(CsrfTokenMismatchException::class)]
final class CsrfTokenMismatchExceptionTest extends TestCase
{
    #[Test]
    public function testExtendsRuntimeException(): void
    {
        $exception = new CsrfTokenMismatchException('test');

        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    #[Test]
    public function testMissingToken(): void
    {
        $exception = CsrfTokenMismatchException::missingToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfTokenMismatchException::class, $exception);
        $this->assertSame('CSRF token is missing from the request', $exception->getMessage());
    }

    #[Test]
    public function testExpiredToken(): void
    {
        $exception = CsrfTokenMismatchException::expiredToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfTokenMismatchException::class, $exception);
        $this->assertSame('CSRF token has expired', $exception->getMessage());
    }

    #[Test]
    public function testTokenMismatch(): void
    {
        $exception = CsrfTokenMismatchException::tokenMismatch();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfTokenMismatchException::class, $exception);
        $this->assertSame('CSRF token validation failed', $exception->getMessage());
    }

    #[Test]
    public function testNoStoredToken(): void
    {
        $exception = CsrfTokenMismatchException::noStoredToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfTokenMismatchException::class, $exception);
        $this->assertSame('No CSRF token found in storage', $exception->getMessage());
    }

    #[Test]
    public function testCustomMessage(): void
    {
        $exception = new CsrfTokenMismatchException('Custom error message');

        $this->assertSame('Custom error message', $exception->getMessage());
    }
}
