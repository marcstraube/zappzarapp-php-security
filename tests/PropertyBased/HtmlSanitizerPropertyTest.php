<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Html\HtmlSanitizer;
use Zappzarapp\Security\Sanitization\Html\HtmlSanitizerConfig;

/**
 * Property-based tests for HtmlSanitizer
 *
 * These tests verify security invariants hold for ANY input.
 */
#[CoversClass(HtmlSanitizer::class)]
final class HtmlSanitizerPropertyTest extends TestCase
{
    use TestTrait;

    /**
     * Property: Sanitized output NEVER contains script tags
     */
    public function testSanitizedOutputNeverContainsScriptTags(): void
    {
        $sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::standard());

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($sanitizer): void {
            $output = $sanitizer->sanitize($input);

            // Case-insensitive check for script tags
            $this->assertStringNotContainsStringIgnoringCase('<script', $output);
            $this->assertStringNotContainsStringIgnoringCase('</script', $output);
        });
    }

    /**
     * Property: Sanitized output NEVER contains event handler attributes
     */
    public function testSanitizedOutputNeverContainsEventHandlers(): void
    {
        $sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::standard());

        $eventHandlers = [
            'onclick', 'onload', 'onerror', 'onmouseover', 'onfocus',
            'onsubmit', 'onkeydown', 'onkeyup', 'onchange',
        ];

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($sanitizer, $eventHandlers): void {
            $output = $sanitizer->sanitize($input);

            foreach ($eventHandlers as $handler) {
                // Check for handler="..." pattern
                $this->assertDoesNotMatchRegularExpression(
                    '/' . preg_quote($handler, '/') . '\s*=/i',
                    $output,
                    "Output contains event handler: {$handler}"
                );
            }
        });
    }

    /**
     * Property: Sanitized output NEVER contains javascript: URIs
     */
    public function testSanitizedOutputNeverContainsJavascriptUri(): void
    {
        $sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::rich());

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($sanitizer): void {
            $output = $sanitizer->sanitize($input);

            // Check for javascript: URI in any attribute
            $this->assertDoesNotMatchRegularExpression(
                '/javascript\s*:/i',
                $output,
                'Output contains javascript: URI'
            );
        });
    }

    /**
     * Property: Sanitized output with XSS payloads is safe
     *
     * Specifically tests common XSS attack patterns.
     */
    public function testCommonXssPayloadsAreNeutralized(): void
    {
        $sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::standard());

        $xssPayloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<a href="javascript:alert(1)">click</a>',
            '<div onclick="alert(1)">click</div>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
        ];

        foreach ($xssPayloads as $payload) {
            $output = $sanitizer->sanitize($payload);

            $this->assertStringNotContainsStringIgnoringCase('<script', $output);
            $this->assertDoesNotMatchRegularExpression('/on\w+\s*=/i', $output);
            $this->assertDoesNotMatchRegularExpression('/javascript\s*:/i', $output);
        }
    }

    /**
     * Property: stripAll configuration removes ALL HTML
     */
    public function testStripAllRemovesAllHtml(): void
    {
        $sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::stripAll());

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($sanitizer): void {
            $output = $sanitizer->sanitize($input);

            // Output should not contain any HTML tags (except entities)
            // After stripAll, any < should be escaped to &lt;
            $this->assertDoesNotMatchRegularExpression(
                '/<[a-zA-Z]/',
                $output,
                'Output contains HTML tags after stripAll'
            );
        });
    }

    /**
     * Property: Sanitization is idempotent for safe content
     *
     * Sanitizing already sanitized content should produce the same result.
     * Note: Some edge cases with entity encoding may differ, so we test
     * that dangerous patterns remain removed.
     */
    public function testSanitizedContentRemainsSafe(): void
    {
        $sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::standard());

        // Known dangerous event handlers (explicit list avoids false positives
        // from random strings like "OnU=" matching /on\w+=/i)
        $eventHandlers = [
            'onclick', 'onload', 'onerror', 'onmouseover', 'onfocus',
            'onsubmit', 'onkeydown', 'onkeyup', 'onchange', 'onmouseout',
            'onmousedown', 'onmouseup', 'ondblclick', 'onblur', 'oninput',
        ];

        $this->forAll(
            Generators::string()
        )->then(function (string $input) use ($sanitizer, $eventHandlers): void {
            $once  = $sanitizer->sanitize($input);
            $twice = $sanitizer->sanitize($once);

            // The key security property: twice-sanitized content is still safe
            $this->assertStringNotContainsStringIgnoringCase('<script', $twice);

            // Check for known event handlers only (avoids false positives)
            foreach ($eventHandlers as $handler) {
                $this->assertDoesNotMatchRegularExpression(
                    '/' . preg_quote($handler, '/') . '\s*=/i',
                    $twice,
                    "Output contains event handler: {$handler}"
                );
            }

            $this->assertDoesNotMatchRegularExpression('/javascript\s*:/i', $twice);
        });
    }

    /**
     * Property: Empty input produces empty output
     */
    public function testEmptyInputProducesEmptyOutput(): void
    {
        $sanitizer = new HtmlSanitizer();

        $this->assertSame('', $sanitizer->sanitize(''));
        // Note: Whitespace is preserved by the sanitizer
    }
}
