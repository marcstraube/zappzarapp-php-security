<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Path;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Exception\PathTraversalException;
use Zappzarapp\Security\Sanitization\Path\PathValidationConfig;
use Zappzarapp\Security\Sanitization\Path\PathValidator;

#[CoversClass(PathValidator::class)]
final class PathValidatorTest extends TestCase
{
    private PathValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new PathValidator();
    }

    public function testValidateAcceptsValidPath(): void
    {
        $this->validator->validate('/var/www/html/file.txt');
        $this->validator->validate('uploads/image.jpg');
        $this->validator->validate('file.txt');

        $this->assertTrue(true);
    }

    public function testValidateRejectsNullByte(): void
    {
        $this->expectException(PathTraversalException::class);
        $this->expectExceptionMessage('Null byte');

        $this->validator->validate("/var/www/html/file.txt\0.php");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function traversalPathProvider(): array
    {
        return [
            'dotdot slash'          => ['../etc/passwd'],
            'double dotdot'         => ['../../etc/passwd'],
            'slash dotdot'          => ['/var/www/../etc/passwd'],
            'backslash dotdot'      => ['..\\etc\\passwd'],
            'just dotdot'           => ['..'],
            'ends with dotdot'      => ['/var/..'],
            'encoded dotdot'        => ['%2e%2e/etc/passwd'],
            'double encoded'        => ['%252e%252e/etc/passwd'],
            'mixed encoding'        => ['..%2fetc/passwd'],
        ];
    }

    #[DataProvider('traversalPathProvider')]
    public function testValidateRejectsTraversal(string $path): void
    {
        $this->expectException(PathTraversalException::class);

        $this->validator->validate($path);
    }

    public function testIsSafeReturnsTrue(): void
    {
        $this->assertTrue($this->validator->isSafe('/var/www/html/file.txt'));
        $this->assertTrue($this->validator->isSafe('uploads/image.jpg'));
    }

    public function testIsSafeReturnsFalse(): void
    {
        $this->assertFalse($this->validator->isSafe('../etc/passwd'));
        $this->assertFalse($this->validator->isSafe("/file.txt\0.php"));
    }

    public function testNormalize(): void
    {
        $validator = new PathValidator(new PathValidationConfig(normalizePath: true));

        $normalized = $validator->normalize('uploads\\file.txt');
        $this->assertSame('uploads/file.txt', $normalized);
    }

    public function testNormalizeRemovesRedundantSlashes(): void
    {
        $validator = new PathValidator(new PathValidationConfig(normalizePath: true));

        $normalized = $validator->normalize('uploads//path///file.txt');
        $this->assertSame('uploads/path/file.txt', $normalized);
    }

    public function testNormalizeRemovesTrailingSlash(): void
    {
        $validator = new PathValidator(new PathValidationConfig(normalizePath: true));

        $normalized = $validator->normalize('uploads/path/');
        $this->assertSame('uploads/path', $normalized);
    }

    public function testNormalizeKeepsRootSlash(): void
    {
        $validator = new PathValidator(new PathValidationConfig(normalizePath: true));

        $normalized = $validator->normalize('/');
        $this->assertSame('/', $normalized);
    }

    public function testNormalizeWithoutNormalizationEnabled(): void
    {
        $validator = new PathValidator(new PathValidationConfig(normalizePath: false));

        $normalized = $validator->normalize('uploads\\file.txt');
        $this->assertSame('uploads\\file.txt', $normalized);
    }

    public function testValidateRejectsDotFiles(): void
    {
        $validator = new PathValidator(new PathValidationConfig(allowDotFiles: false));

        $this->expectException(PathTraversalException::class);

        $validator->validate('/var/www/.htaccess');
    }

    public function testValidateAllowsDotFilesWhenEnabled(): void
    {
        $validator = new PathValidator(new PathValidationConfig(allowDotFiles: true));

        $validator->validate('/var/www/.htaccess');

        $this->assertTrue(true);
    }

    public function testValidateRejectsBlockedExtensions(): void
    {
        $validator = new PathValidator(new PathValidationConfig(blockedExtensions: ['php', 'phtml']));

        $this->expectException(PathTraversalException::class);

        $validator->validate('/var/www/shell.php');
    }

    public function testValidateAllowsNonBlockedExtensions(): void
    {
        $validator = new PathValidator(new PathValidationConfig(blockedExtensions: ['php', 'phtml']));

        $validator->validate('/var/www/image.jpg');
        $validator->validate('/var/www/document.pdf');

        $this->assertTrue(true);
    }

    public function testValidateWithBasePath(): void
    {
        $basePath  = sys_get_temp_dir();
        $validator = new PathValidator(new PathValidationConfig(basePath: $basePath));

        $validator->validate($basePath . '/file.txt');

        $this->assertTrue(true);
    }

    public function testValidateRejectsPathOutsideBasePath(): void
    {
        $basePath  = sys_get_temp_dir() . '/test-' . uniqid();
        @mkdir($basePath);
        $validator = new PathValidator(new PathValidationConfig(basePath: $basePath));

        $this->expectException(PathTraversalException::class);

        try {
            $validator->validate('/etc/passwd');
        } finally {
            @rmdir($basePath);
        }
    }

    public function testValidateDetectsSymlinksInPath(): void
    {
        // Create a test directory structure with a symlink
        $basePath = sys_get_temp_dir() . '/path-test-' . uniqid();
        $realDir  = $basePath . '/real';
        $linkPath = $basePath . '/link';
        $testFile = $realDir . '/test.txt';

        @mkdir($basePath);
        @mkdir($realDir);
        file_put_contents($testFile, 'test content');
        @symlink($realDir, $linkPath);

        $validator = new PathValidator(new PathValidationConfig(
            basePath: $basePath,
            allowSymlinks: false
        ));

        try {
            // Accessing through the symlink should throw
            $this->expectException(PathTraversalException::class);
            $validator->validate($linkPath . '/test.txt');
        } finally {
            // Cleanup
            @unlink($linkPath);
            @unlink($testFile);
            @rmdir($realDir);
            @rmdir($basePath);
        }
    }

    public function testValidateAllowsSymlinksWhenEnabled(): void
    {
        // Create a test directory structure with a symlink
        $basePath = sys_get_temp_dir() . '/path-test-' . uniqid();
        $realDir  = $basePath . '/real';
        $linkPath = $basePath . '/link';
        $testFile = $realDir . '/test.txt';

        @mkdir($basePath);
        @mkdir($realDir);
        file_put_contents($testFile, 'test content');
        @symlink($realDir, $linkPath);

        $validator = new PathValidator(new PathValidationConfig(
            basePath: $basePath,
            allowSymlinks: true
        ));

        try {
            // Should not throw when symlinks are allowed
            $validator->validate($linkPath . '/test.txt');
            $this->assertTrue(true); // Assert that we reached this point
        } finally {
            // Cleanup
            @unlink($linkPath);
            @unlink($testFile);
            @rmdir($realDir);
            @rmdir($basePath);
        }
    }

    public function testValidateChecksEntirePathForSymlinks(): void
    {
        // Create a nested structure with a symlink in the middle
        $basePath  = sys_get_temp_dir() . '/nested-test-' . uniqid();
        $realDir   = $basePath . '/real';
        $nestedDir = $realDir . '/nested';
        $linkPath  = $basePath . '/link';

        @mkdir($basePath);
        @mkdir($realDir);
        @mkdir($nestedDir);
        @symlink($realDir, $linkPath);
        file_put_contents($nestedDir . '/file.txt', 'content');

        $validator = new PathValidator(new PathValidationConfig(
            basePath: $basePath,
            allowSymlinks: false
        ));

        try {
            // The symlink is in the path to the file
            $this->expectException(PathTraversalException::class);
            $validator->validate($linkPath . '/nested/file.txt');
        } finally {
            // Cleanup
            @unlink($nestedDir . '/file.txt');
            @rmdir($nestedDir);
            @unlink($linkPath);
            @rmdir($realDir);
            @rmdir($basePath);
        }
    }

    public function testValidateHandlesRootPathInSymlinkCheck(): void
    {
        // Edge case: test with root-relative path
        $validator = new PathValidator(new PathValidationConfig(
            basePath: '/tmp',
            allowSymlinks: false
        ));

        // /tmp itself should be valid even though it might resolve to a symlink on some systems
        // The important thing is the loop handles the root case
        $validator->validate('/tmp/test-file-' . uniqid());
        $this->assertTrue(true);
    }

    public function testValidateHandlesDotPathInSymlinkCheck(): void
    {
        // Edge case: relative path starting with .
        $validator = new PathValidator(new PathValidationConfig(
            allowSymlinks: false
        ));

        // This should not infinite loop
        $validator->validate('./file.txt');
        $this->assertTrue(true);
    }

    public function testValidateRejectsSymlinkForNonExistentFile(): void
    {
        // Test case: file doesn't exist, but parent directory contains a symlink
        $basePath = sys_get_temp_dir() . '/symlink-nonexist-' . uniqid();
        $realDir  = $basePath . '/real';
        $linkPath = $basePath . '/link';

        @mkdir($basePath);
        @mkdir($realDir);
        @symlink($realDir, $linkPath);

        $validator = new PathValidator(new PathValidationConfig(
            basePath: $basePath,
            allowSymlinks: false
        ));

        try {
            // File doesn't exist, but the parent path contains a symlink
            // The symlink check should trigger for the parent directory
            $this->expectException(PathTraversalException::class);
            $validator->validate($linkPath . '/nonexistent-file.txt');
        } finally {
            @unlink($linkPath);
            @rmdir($realDir);
            @rmdir($basePath);
        }
    }

    public function testValidateAllowsNonExistentFileWithSymlinksEnabled(): void
    {
        // Test case: file doesn't exist, symlinks allowed
        $basePath = sys_get_temp_dir() . '/symlink-allow-' . uniqid();
        $realDir  = $basePath . '/real';
        $linkPath = $basePath . '/link';

        @mkdir($basePath);
        @mkdir($realDir);
        @symlink($realDir, $linkPath);

        $validator = new PathValidator(new PathValidationConfig(
            basePath: $basePath,
            allowSymlinks: true
        ));

        try {
            // With symlinks allowed, this should pass
            $validator->validate($linkPath . '/nonexistent.txt');
            $this->assertTrue(true);
        } finally {
            @unlink($linkPath);
            @rmdir($realDir);
            @rmdir($basePath);
        }
    }

    public function testValidateWithAbsolutePathReachingRoot(): void
    {
        // Test symlink check loop termination at root '/'
        $validator = new PathValidator(new PathValidationConfig(
            basePath: '/tmp',
            allowSymlinks: false
        ));

        // A deeply nested path that will traverse up to root
        $deepPath = '/tmp/a/b/c/d/file.txt';
        @mkdir('/tmp/a/b/c/d', 0777, true);

        try {
            $validator->validate($deepPath);
            $this->assertTrue(true);
        } finally {
            @rmdir('/tmp/a/b/c/d');
            @rmdir('/tmp/a/b/c');
            @rmdir('/tmp/a/b');
            @rmdir('/tmp/a');
        }
    }

    public function testValidateWithEmptyPathComponent(): void
    {
        // Test handling of paths with empty segments
        $validator = new PathValidator(new PathValidationConfig(
            allowSymlinks: false
        ));

        // Path with empty component (double slash) - gets normalized
        $validator->validate('/tmp//file.txt');
        $this->assertTrue(true);
    }

    public function testValidateRejectsPathWhenBasePathDoesNotExist(): void
    {
        // Test case: base path that doesn't exist
        $nonExistentBasePath = '/nonexistent-path-' . uniqid() . '/subdir';
        $validator           = new PathValidator(new PathValidationConfig(basePath: $nonExistentBasePath));

        $this->expectException(PathTraversalException::class);

        $validator->validate('/tmp/file.txt');
    }
}
