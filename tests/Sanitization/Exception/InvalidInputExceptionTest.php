<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Exception\InvalidInputException;

#[CoversClass(InvalidInputException::class)]
final class InvalidInputExceptionTest extends TestCase
{
    // =========================================================================
    // Exception Base Class
    // =========================================================================

    public function testExtendsInvalidArgumentException(): void
    {
        $exception = InvalidInputException::malformed('test', 'reason');

        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
    }

    // =========================================================================
    // Factory Method: malformed()
    // =========================================================================

    public function testMalformedCreatesExceptionWithCorrectMessage(): void
    {
        $exception = InvalidInputException::malformed('JSON', 'unexpected token');

        $this->assertSame('Invalid JSON input: unexpected token', $exception->getMessage());
    }

    #[DataProvider('malformedInputProvider')]
    public function testMalformedWithVariousInputTypes(string $type, string $reason, string $expected): void
    {
        $exception = InvalidInputException::malformed($type, $reason);

        $this->assertSame($expected, $exception->getMessage());
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function malformedInputProvider(): iterable
    {
        yield 'html type' => [
            'HTML',
            'unclosed tag',
            'Invalid HTML input: unclosed tag',
        ];

        yield 'xml type' => [
            'XML',
            'missing root element',
            'Invalid XML input: missing root element',
        ];

        yield 'url type' => [
            'URL',
            'invalid scheme',
            'Invalid URL input: invalid scheme',
        ];

        yield 'empty type' => [
            '',
            'empty not allowed',
            'Invalid  input: empty not allowed',
        ];

        yield 'empty reason' => [
            'data',
            '',
            'Invalid data input: ',
        ];
    }

    // =========================================================================
    // Factory Method: unsafeContent()
    // =========================================================================

    public function testUnsafeContentCreatesExceptionWithCorrectMessage(): void
    {
        $exception = InvalidInputException::unsafeContent('HTML', 'script injection detected');

        $this->assertSame('Unsafe HTML content detected: script injection detected', $exception->getMessage());
    }

    #[DataProvider('unsafeContentProvider')]
    public function testUnsafeContentWithVariousInputTypes(string $type, string $reason, string $expected): void
    {
        $exception = InvalidInputException::unsafeContent($type, $reason);

        $this->assertSame($expected, $exception->getMessage());
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function unsafeContentProvider(): iterable
    {
        yield 'xss detection' => [
            'HTML',
            'XSS payload detected',
            'Unsafe HTML content detected: XSS payload detected',
        ];

        yield 'sql injection' => [
            'SQL',
            'potential SQL injection',
            'Unsafe SQL content detected: potential SQL injection',
        ];

        yield 'command injection' => [
            'shell',
            'command injection attempt',
            'Unsafe shell content detected: command injection attempt',
        ];

        yield 'empty type' => [
            '',
            'dangerous pattern',
            'Unsafe  content detected: dangerous pattern',
        ];
    }

    // =========================================================================
    // Factory Method: invalidEncoding()
    // =========================================================================

    public function testInvalidEncodingCreatesExceptionWithCorrectMessage(): void
    {
        $exception = InvalidInputException::invalidEncoding('UTF-8');

        $this->assertSame('Input is not valid UTF-8', $exception->getMessage());
    }

    #[DataProvider('invalidEncodingProvider')]
    public function testInvalidEncodingWithVariousEncodings(string $expected, string $expectedMessage): void
    {
        $exception = InvalidInputException::invalidEncoding($expected);

        $this->assertSame($expectedMessage, $exception->getMessage());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function invalidEncodingProvider(): iterable
    {
        yield 'utf-8' => [
            'UTF-8',
            'Input is not valid UTF-8',
        ];

        yield 'ascii' => [
            'ASCII',
            'Input is not valid ASCII',
        ];

        yield 'iso-8859-1' => [
            'ISO-8859-1',
            'Input is not valid ISO-8859-1',
        ];

        yield 'empty encoding' => [
            '',
            'Input is not valid ',
        ];
    }

    // =========================================================================
    // Security: Exception Messages Do Not Expose Sensitive Data
    // =========================================================================

    public function testMalformedDoesNotIncludeActualInput(): void
    {
        $sensitiveInput = 'password=secret123&token=abc';
        $exception      = InvalidInputException::malformed('form', 'validation failed');

        // The exception message should not contain the actual sensitive input
        $this->assertStringNotContainsString($sensitiveInput, $exception->getMessage());
        $this->assertStringNotContainsString('secret123', $exception->getMessage());
    }

    public function testUnsafeContentDoesNotIncludeActualPayload(): void
    {
        $xssPayload = '<script>document.cookie</script>';
        $exception  = InvalidInputException::unsafeContent('HTML', 'XSS detected');

        // The exception message should not contain the actual payload
        $this->assertStringNotContainsString($xssPayload, $exception->getMessage());
        $this->assertStringNotContainsString('document.cookie', $exception->getMessage());
    }

    // =========================================================================
    // Immutability: Each Call Creates New Instance
    // =========================================================================

    public function testFactoryMethodsCreateNewInstances(): void
    {
        $exception1 = InvalidInputException::malformed('type1', 'reason1');
        $exception2 = InvalidInputException::malformed('type1', 'reason1');

        $this->assertNotSame($exception1, $exception2);
    }

    public function testDifferentFactoryMethodsCreateDistinctExceptions(): void
    {
        $malformed  = InvalidInputException::malformed('test', 'reason');
        $unsafe     = InvalidInputException::unsafeContent('test', 'reason');
        $encoding   = InvalidInputException::invalidEncoding('UTF-8');

        $this->assertNotSame($malformed->getMessage(), $unsafe->getMessage());
        $this->assertNotSame($malformed->getMessage(), $encoding->getMessage());
        $this->assertNotSame($unsafe->getMessage(), $encoding->getMessage());
    }
}
