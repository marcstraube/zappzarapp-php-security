<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;

#[CoversClass(InvalidCsrfTokenException::class)]
final class InvalidCsrfTokenExceptionTest extends TestCase
{
    public function testExtendsInvalidArgumentException(): void
    {
        $exception = new InvalidCsrfTokenException('test');

        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
    }

    public function testEmptyToken(): void
    {
        $exception = InvalidCsrfTokenException::emptyToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(InvalidCsrfTokenException::class, $exception);
        $this->assertSame('CSRF token cannot be empty', $exception->getMessage());
    }

    public function testInvalidFormat(): void
    {
        $exception = InvalidCsrfTokenException::invalidFormat('bad-token', 'contains special chars');

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(InvalidCsrfTokenException::class, $exception);
        $this->assertStringContainsString('contains special chars', $exception->getMessage());
        $this->assertStringContainsString('bad-token', $exception->getMessage());
    }

    public function testInvalidFormatEscapesNewlines(): void
    {
        $exception = InvalidCsrfTokenException::invalidFormat("token\r\nwith\nnewlines", 'control chars');

        $message = $exception->getMessage();
        $this->assertStringContainsString('\\r', $message);
        $this->assertStringContainsString('\\n', $message);
        $this->assertStringNotContainsString("\r", $message);
        $this->assertStringNotContainsString("\n", $message);
    }

    public function testInvalidBase64(): void
    {
        $exception = InvalidCsrfTokenException::invalidBase64('not!base64!!!');

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(InvalidCsrfTokenException::class, $exception);
        $this->assertStringContainsString('not valid base64', $exception->getMessage());
        $this->assertStringContainsString('not!base64!!!', $exception->getMessage());
    }

    public function testInsufficientEntropy(): void
    {
        $exception = InvalidCsrfTokenException::insufficientEntropy(32, 16);

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(InvalidCsrfTokenException::class, $exception);
        $this->assertStringContainsString('insufficient entropy', $exception->getMessage());
        $this->assertStringContainsString('32', $exception->getMessage());
        $this->assertStringContainsString('16', $exception->getMessage());
    }

    public function testCustomMessage(): void
    {
        $exception = new InvalidCsrfTokenException('Custom validation error');

        $this->assertSame('Custom validation error', $exception->getMessage());
    }
}
