<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Exception\PathTraversalException;
use Zappzarapp\Security\Sanitization\Path\PathValidationConfig;
use Zappzarapp\Security\Sanitization\Path\PathValidator;

/**
 * Property-based tests for PathValidator
 *
 * These tests verify security invariants hold for ANY input.
 */
#[CoversClass(PathValidator::class)]
final class PathValidatorPropertyTest extends TestCase
{
    use TestTrait;

    /**
     * Property: Paths with null bytes are ALWAYS rejected
     */
    #[Test]
    public function testPathsWithNullBytesAreAlwaysRejected(): void
    {
        $validator = new PathValidator();

        $this->forAll(
            Generators::string(),
            Generators::string()
        )->then(function (string $before, string $after) use ($validator): void {
            $pathWithNull = $before . "\0" . $after;

            $this->assertFalse(
                $validator->isSafe($pathWithNull),
                'Path with null byte should be rejected'
            );
        });
    }

    /**
     * Property: Paths with traversal sequences are ALWAYS rejected
     */
    #[Test]
    public function testPathsWithTraversalAreAlwaysRejected(): void
    {
        $validator = new PathValidator();

        $traversalPatterns = [
            '../',
            '..\\',
            '/../../',
            '\\..\\..\\',
            '....//....//....//',
        ];

        $this->forAll(
            Generators::string(),
            Generators::elements($traversalPatterns),
            Generators::string()
        )->then(function (string $before, string $traversal, string $after) use ($validator): void {
            // Clean the before/after to avoid null bytes (tested separately)
            $before = str_replace("\0", '', $before);
            $after  = str_replace("\0", '', $after);

            $pathWithTraversal = $before . $traversal . $after;

            $this->assertFalse(
                $validator->isSafe($pathWithTraversal),
                "Path with traversal should be rejected: {$pathWithTraversal}"
            );
        });
    }

    /**
     * Property: URL-encoded traversal sequences are ALWAYS rejected
     */
    #[Test]
    public function testEncodedTraversalIsRejected(): void
    {
        $validator = new PathValidator();

        $encodedPatterns = [
            '%2e%2e%2f',          // ../
            '%2e%2e/',           // ../
            '..%2f',              // ../
            '%2e%2e%5c',          // ..\
            '..%5c',              // ..\
            '%252e%252e%252f',    // double-encoded ../
        ];

        foreach ($encodedPatterns as $encoded) {
            $this->assertFalse(
                $validator->isSafe('/safe/path/' . $encoded . 'file'),
                "Encoded traversal should be rejected: {$encoded}"
            );
        }
    }

    /**
     * Property: Common path traversal attack patterns are rejected
     */
    #[Test]
    public function testCommonTraversalAttacksAreRejected(): void
    {
        $validator = new PathValidator();

        $attacks = [
            '../../../etc/passwd',
            "..\\..\\..\\windows\\system32\\config\\sam",
            '/var/www/html/../../../etc/shadow',
            'uploads/../../config.php',
            '....//....//etc/passwd',
            '..%00/etc/passwd',
            '../file.txt%00.jpg',
            "/path/to/file\0.txt",  // actual null byte (double quotes)
        ];

        foreach ($attacks as $attack) {
            $this->assertFalse(
                $validator->isSafe($attack),
                "Attack pattern should be rejected: {$attack}"
            );
        }
    }

    /**
     * Property: Safe paths are preserved
     */
    #[Test]
    public function testSafePathsArePreserved(): void
    {
        $validator = new PathValidator(new PathValidationConfig(allowDotFiles: true));

        $safePaths = [
            'file.txt',
            '/var/www/html/file.txt',
            '/home/user/documents/report.pdf',
            'uploads/images/photo.jpg',
            'data/2024/01/file.csv',
        ];

        foreach ($safePaths as $path) {
            $this->assertTrue(
                $validator->isSafe($path),
                "Safe path should be allowed: {$path}"
            );
        }
    }

    /**
     * Property: Normalized paths never contain traversal sequences
     */
    #[Test]
    public function testNormalizedPathsNeverContainTraversal(): void
    {
        $validator = new PathValidator();

        // Safe inputs only (no traversal)
        $this->forAll(
            Generators::suchThat(
                fn(string $s): bool => !str_contains($s, '..') && !str_contains($s, "\0"),
                Generators::string()
            )
        )->then(function (string $input) use ($validator): void {
            if (!$validator->isSafe($input)) {
                return; // Skip invalid paths
            }

            $normalized = $validator->normalize($input);

            $this->assertStringNotContainsString('../', $normalized);
            $this->assertStringNotContainsString('..\\', $normalized);
            $this->assertStringNotContainsString("\0", $normalized);
        });
    }

    /**
     * Property: Dot files are blocked by default
     */
    #[Test]
    public function testDotFilesBlockedByDefault(): void
    {
        $validator = new PathValidator(new PathValidationConfig(allowDotFiles: false));

        $dotFiles = [
            '.htaccess',
            '.env',
            '.gitignore',
            '/var/www/.env',
            'uploads/.hidden',
        ];

        foreach ($dotFiles as $path) {
            $this->assertFalse(
                $validator->isSafe($path),
                "Dot file should be blocked: {$path}"
            );
        }
    }

    /**
     * Property: Blocked extensions are rejected
     */
    #[Test]
    public function testBlockedExtensionsAreRejected(): void
    {
        $validator = new PathValidator(new PathValidationConfig(
            blockedExtensions: ['php', 'phar', 'phtml', 'sh', 'exe'],
        ));

        $blockedFiles = [
            'malware.php',
            'evil.phar',
            'shell.sh',
            'virus.exe',
            '/uploads/backdoor.phtml',
        ];

        foreach ($blockedFiles as $path) {
            $this->assertFalse(
                $validator->isSafe($path),
                "Blocked extension should be rejected: {$path}"
            );
        }
    }

    /**
     * Property: isSafe is consistent with validate()
     */
    #[Test]
    public function testIsSafeConsistentWithValidate(): void
    {
        $validator = new PathValidator();

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($validator): void {
            $isSafe = $validator->isSafe($input);

            try {
                $validator->validate($input);
                $didValidate = true;
            } catch (PathTraversalException) {
                $didValidate = false;
            }

            $this->assertSame(
                $isSafe,
                $didValidate,
                'isSafe() and validate() should be consistent'
            );
        });
    }
}
