<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Sanitization\Exception\PathTraversalException;

#[CoversClass(PathTraversalException::class)]
final class PathTraversalExceptionTest extends TestCase
{
    // =========================================================================
    // Exception Base Class
    // =========================================================================

    #[Test]
    public function testExtendsRuntimeException(): void
    {
        $exception = PathTraversalException::traversalDetected('/etc/../passwd');

        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    // =========================================================================
    // Factory Method: traversalDetected()
    // =========================================================================

    #[Test]
    public function testTraversalDetectedCreatesExceptionWithCorrectMessage(): void
    {
        $exception = PathTraversalException::traversalDetected('/var/www/../../../etc/passwd');

        $this->assertSame('Path traversal detected in: /var/www/../../../etc/passwd', $exception->getMessage());
    }

    #[DataProvider('traversalPathProvider')]
    #[Test]
    public function testTraversalDetectedWithVariousPaths(string $path, string $expected): void
    {
        $exception = PathTraversalException::traversalDetected($path);

        $this->assertSame($expected, $exception->getMessage());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function traversalPathProvider(): iterable
    {
        yield 'simple traversal' => [
            '../secret.txt',
            'Path traversal detected in: ../secret.txt',
        ];

        yield 'double traversal' => [
            '../../etc/passwd',
            'Path traversal detected in: ../../etc/passwd',
        ];

        yield 'windows traversal' => [
            '..\\..\\windows\\system32',
            'Path traversal detected in: ..\\..\\windows\\system32',
        ];

        yield 'encoded traversal' => [
            '%2e%2e%2f%2e%2e%2fetc/passwd',
            'Path traversal detected in: %2e%2e%2f%2e%2e%2fetc/passwd',
        ];

        yield 'double encoded' => [
            '%252e%252e%252f',
            'Path traversal detected in: %252e%252e%252f',
        ];

        yield 'unicode normalized' => [
            '．．／etc/passwd',
            'Path traversal detected in: ．．／etc/passwd',
        ];

        yield 'empty path' => [
            '',
            'Path traversal detected in: ',
        ];
    }

    // =========================================================================
    // Factory Method: nullByteDetected()
    // =========================================================================

    #[Test]
    public function testNullByteDetectedCreatesExceptionWithCorrectMessage(): void
    {
        $exception = PathTraversalException::nullByteDetected("/var/www/file.txt\0.jpg");

        $this->assertSame('Null byte detected in path: /var/www/file.txt\\0.jpg', $exception->getMessage());
    }

    #[Test]
    public function testNullByteDetectedEscapesNullBytes(): void
    {
        $pathWithNullByte = "test\0file";
        $exception        = PathTraversalException::nullByteDetected($pathWithNullByte);

        // Null byte should be escaped as \0 in the message
        $this->assertStringContainsString('\\0', $exception->getMessage());
        $this->assertStringNotContainsString("\0", $exception->getMessage());
    }

    #[DataProvider('nullBytePathProvider')]
    #[Test]
    public function testNullByteDetectedWithVariousPaths(string $path, string $expected): void
    {
        $exception = PathTraversalException::nullByteDetected($path);

        $this->assertSame($expected, $exception->getMessage());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function nullBytePathProvider(): iterable
    {
        yield 'null byte in filename' => [
            "file.php\0.jpg",
            'Null byte detected in path: file.php\\0.jpg',
        ];

        yield 'multiple null bytes' => [
            "test\0file\0name",
            'Null byte detected in path: test\\0file\\0name',
        ];

        yield 'null byte at start' => [
            "\0hidden",
            'Null byte detected in path: \\0hidden',
        ];

        yield 'null byte at end' => [
            "file.txt\0",
            'Null byte detected in path: file.txt\\0',
        ];

        yield 'no null byte' => [
            'normal/path/file.txt',
            'Null byte detected in path: normal/path/file.txt',
        ];

        yield 'empty path' => [
            '',
            'Null byte detected in path: ',
        ];
    }

    // =========================================================================
    // Factory Method: outsideBasePath()
    // =========================================================================

    #[Test]
    public function testOutsideBasePathCreatesExceptionWithCorrectMessage(): void
    {
        $exception = PathTraversalException::outsideBasePath('/etc/passwd', '/var/www');

        $this->assertSame('Path "/etc/passwd" is outside allowed directory "/var/www"', $exception->getMessage());
    }

    #[DataProvider('outsideBasePathProvider')]
    #[Test]
    public function testOutsideBasePathWithVariousPaths(string $path, string $basePath, string $expected): void
    {
        $exception = PathTraversalException::outsideBasePath($path, $basePath);

        $this->assertSame($expected, $exception->getMessage());
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function outsideBasePathProvider(): iterable
    {
        yield 'absolute path outside base' => [
            '/etc/passwd',
            '/var/www',
            'Path "/etc/passwd" is outside allowed directory "/var/www"',
        ];

        yield 'relative path resolved outside' => [
            '/var/log/syslog',
            '/var/www/html',
            'Path "/var/log/syslog" is outside allowed directory "/var/www/html"',
        ];

        yield 'root path' => [
            '/',
            '/var/www',
            'Path "/" is outside allowed directory "/var/www"',
        ];

        yield 'empty path' => [
            '',
            '/var/www',
            'Path "" is outside allowed directory "/var/www"',
        ];

        yield 'empty base path' => [
            '/etc/passwd',
            '',
            'Path "/etc/passwd" is outside allowed directory ""',
        ];

        yield 'both empty' => [
            '',
            '',
            'Path "" is outside allowed directory ""',
        ];
    }

    // =========================================================================
    // Security: Message Content
    // =========================================================================

    #[Test]
    public function testTraversalMessageIncludesPathForLogging(): void
    {
        $maliciousPath = '../../../etc/shadow';
        $exception     = PathTraversalException::traversalDetected($maliciousPath);

        // Path should be included for logging/debugging purposes
        $this->assertStringContainsString($maliciousPath, $exception->getMessage());
    }

    #[Test]
    public function testNullByteMessageEscapesForSafeLogging(): void
    {
        $pathWithNullByte = "upload\0.php";
        $exception        = PathTraversalException::nullByteDetected($pathWithNullByte);

        // The actual null byte should not be in the message (escaped)
        $this->assertStringNotContainsString("\0", $exception->getMessage());
        // But the escaped version should be visible
        $this->assertStringContainsString('\\0', $exception->getMessage());
    }

    // =========================================================================
    // Immutability: Each Call Creates New Instance
    // =========================================================================

    #[Test]
    public function testFactoryMethodsCreateNewInstances(): void
    {
        $exception1 = PathTraversalException::traversalDetected('../test');
        $exception2 = PathTraversalException::traversalDetected('../test');

        $this->assertNotSame($exception1, $exception2);
    }

    #[Test]
    public function testDifferentFactoryMethodsCreateDistinctExceptions(): void
    {
        $traversal   = PathTraversalException::traversalDetected('../test');
        $nullByte    = PathTraversalException::nullByteDetected("test\0file");
        $outsideBase = PathTraversalException::outsideBasePath('/etc', '/var');

        $this->assertNotSame($traversal->getMessage(), $nullByte->getMessage());
        $this->assertNotSame($traversal->getMessage(), $outsideBase->getMessage());
        $this->assertNotSame($nullByte->getMessage(), $outsideBase->getMessage());
    }
}
