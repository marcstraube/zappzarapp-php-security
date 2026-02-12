<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;

#[CoversClass(CsrfTokenMismatchException::class)]
final class CsrfTokenMismatchExceptionTest extends TestCase
{
    public function testExtendsRuntimeException(): void
    {
        $exception = new CsrfTokenMismatchException('test');

        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    public function testMissingToken(): void
    {
        $exception = CsrfTokenMismatchException::missingToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfTokenMismatchException::class, $exception);
        $this->assertSame('CSRF token is missing from the request', $exception->getMessage());
    }

    public function testExpiredToken(): void
    {
        $exception = CsrfTokenMismatchException::expiredToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfTokenMismatchException::class, $exception);
        $this->assertSame('CSRF token has expired', $exception->getMessage());
    }

    public function testTokenMismatch(): void
    {
        $exception = CsrfTokenMismatchException::tokenMismatch();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfTokenMismatchException::class, $exception);
        $this->assertSame('CSRF token validation failed', $exception->getMessage());
    }

    public function testNoStoredToken(): void
    {
        $exception = CsrfTokenMismatchException::noStoredToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfTokenMismatchException::class, $exception);
        $this->assertSame('No CSRF token found in storage', $exception->getMessage());
    }

    public function testCustomMessage(): void
    {
        $exception = new CsrfTokenMismatchException('Custom error message');

        $this->assertSame('Custom error message', $exception->getMessage());
    }
}
