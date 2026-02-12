<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizer;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizerConfig;

/**
 * Property-based tests for UriSanitizer
 *
 * These tests verify security invariants hold for ANY input.
 */
#[CoversClass(UriSanitizer::class)]
final class UriSanitizerPropertyTest extends TestCase
{
    use TestTrait;

    /**
     * Property: Sanitized URIs NEVER contain javascript: scheme
     */
    public function testSanitizedUriNeverContainsJavascript(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::web());

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($sanitizer): void {
            $output = $sanitizer->sanitize($input);

            // If output is not empty, it should not contain javascript:
            if ($output !== '') {
                $normalized = strtolower(preg_replace('/\s+/', '', $output) ?? $output);
                $this->assertStringNotContainsString('javascript:', $normalized);
            }
        });
    }

    /**
     * Property: Sanitized URIs NEVER contain vbscript: scheme
     */
    public function testSanitizedUriNeverContainsVbscript(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::web());

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($sanitizer): void {
            $output = $sanitizer->sanitize($input);

            if ($output !== '') {
                $normalized = strtolower(preg_replace('/\s+/', '', $output) ?? $output);
                $this->assertStringNotContainsString('vbscript:', $normalized);
            }
        });
    }

    /**
     * Property: Sanitized URIs NEVER contain data: scheme (by default)
     */
    public function testSanitizedUriNeverContainsDataScheme(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::web());

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($sanitizer): void {
            $output = $sanitizer->sanitize($input);

            if ($output !== '') {
                $normalized = strtolower(preg_replace('/\s+/', '', $output) ?? $output);
                $this->assertStringNotContainsString('data:', $normalized);
            }
        });
    }

    /**
     * Property: Common XSS URI patterns are blocked
     */
    public function testXssUriPatternsAreBlocked(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::web());

        $xssUris = [
            'javascript:alert(1)',
            'JAVASCRIPT:alert(1)',
            'JaVaScRiPt:alert(1)',
            'javascript&#58;alert(1)',
            'javascript&#x3a;alert(1)',
            '  javascript:alert(1)',
            "javascript\t:alert(1)",
            "javascript\n:alert(1)",
            'vbscript:msgbox(1)',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        ];

        foreach ($xssUris as $uri) {
            $output = $sanitizer->sanitize($uri);
            $this->assertSame('', $output, "XSS URI not blocked: {$uri}");
        }
    }

    /**
     * Property: Strict config only allows HTTPS
     */
    public function testStrictConfigOnlyAllowsHttps(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::strict());

        // HTTP should be blocked
        $this->assertSame('', $sanitizer->sanitize('http://example.com'));

        // HTTPS should be allowed
        $this->assertSame('https://example.com', $sanitizer->sanitize('https://example.com'));

        // Relative should be blocked
        $this->assertSame('', $sanitizer->sanitize('/path/to/resource'));
    }

    /**
     * Property: Safe URIs are preserved
     */
    public function testSafeUrisArePreserved(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::web());

        $safeUris = [
            'https://example.com',
            'https://example.com/path',
            'https://example.com/path?query=value',
            'https://example.com/path#fragment',
            'http://localhost:8080',
            'mailto:user@example.com',
            'tel:+1234567890',
            '/relative/path',
            '../parent/path',
            '#anchor',
        ];

        foreach ($safeUris as $uri) {
            $output = $sanitizer->sanitize($uri);
            $this->assertSame($uri, $output, "Safe URI modified: {$uri}");
        }
    }

    /**
     * Property: isSafe returns true for all preserved URIs
     */
    public function testIsSafeConsistentWithSanitize(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::web());

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($sanitizer): void {
            $isSafe    = $sanitizer->isSafe($input);
            $sanitized = $sanitizer->sanitize($input);

            if ($isSafe) {
                // If isSafe returns true, sanitize should return the original (trimmed)
                $this->assertSame(trim($input), $sanitized);
            } else {
                // If isSafe returns false, sanitize should return empty string
                $this->assertSame('', $sanitized);
            }
        });
    }

    /**
     * Property: Empty input is safe
     */
    public function testEmptyInputIsSafe(): void
    {
        $sanitizer = new UriSanitizer();

        $this->assertTrue($sanitizer->isSafe(''));
        $this->assertSame('', $sanitizer->sanitize(''));
    }
}
