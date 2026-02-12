<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\NavigationDirectives;
use Zappzarapp\Security\Csp\Directive\ReportingConfig;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;
use Zappzarapp\Security\Csp\HeaderBuilder;
use Zappzarapp\Security\Csp\Nonce\NullNonce;

/**
 * Property-based tests for CSP header injection prevention
 *
 * These tests verify that CSP directive values are validated
 * to prevent header injection attacks.
 */
#[CoversClass(CspDirectives::class)]
#[CoversClass(NavigationDirectives::class)]
#[CoversClass(ResourceDirectives::class)]
#[CoversClass(ReportingConfig::class)]
final class CspInjectionPropertyTest extends TestCase
{
    use TestTrait;

    /**
     * Property: Semicolons in directive values are ALWAYS rejected
     *
     * Semicolons separate CSP directives. Allowing them in values
     * would enable directive injection attacks.
     */
    public function testSemicolonsInValuesAreRejected(): void
    {
        $this->forAll(
            Generators::string(),
            Generators::string()
        )->then(function (string $before, string $after): void {
            $maliciousValue = $before . ';' . $after;

            // Skip if semicolon was already in the random string
            if (!str_contains($maliciousValue, ';')) {
                return;
            }

            // Try injection in default-src - use reflection to avoid PHPStan issues
            $this->assertThrowsInvalidDirective(fn() => new CspDirectives(defaultSrc: $maliciousValue));

            // Try injection in script-src
            $this->assertThrowsInvalidDirective(fn() => new CspDirectives(scriptSrc: $maliciousValue));
        });
    }

    /**
     * Property: Control characters (CR, LF) are ALWAYS rejected
     *
     * CR/LF could enable HTTP header injection attacks.
     */
    #[DataProvider('controlCharacterProvider')]
    public function testControlCharactersAreRejected(string $char): void
    {
        // Test with a known safe prefix to avoid empty string validation
        $maliciousValue = "'self'" . $char . 'https://evil.com';

        $this->expectException(InvalidDirectiveValueException::class);
        new CspDirectives(defaultSrc: $maliciousValue);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function controlCharacterProvider(): iterable
    {
        yield 'carriage return' => ["\r"];
        yield 'line feed' => ["\n"];
        yield 'crlf' => ["\r\n"];
        yield 'null byte' => ["\x00"];
        yield 'vertical tab' => ["\x0B"];
        yield 'form feed' => ["\x0C"];
    }

    /**
     * Property: HTTP header injection attempts are blocked
     *
     * Attempts to inject new HTTP headers via CSP values are blocked.
     */
    #[DataProvider('headerInjectionProvider')]
    public function testHttpHeaderInjectionIsBlocked(string $attempt): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        new CspDirectives(defaultSrc: $attempt);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function headerInjectionProvider(): iterable
    {
        yield 'crlf injection' => ["'self'\r\nX-Injected: malicious"];
        yield 'lf set-cookie' => ["'self'\nSet-Cookie: session=evil"];
        yield 'crlf location' => ["'self'\r\nLocation: https://evil.com"];
        yield 'null + crlf' => ["'self'\x00\r\nX-Injected: malicious"];
    }

    /**
     * Property: Directive injection attempts are blocked
     *
     * Attempts to inject new CSP directives via semicolon are blocked.
     */
    #[DataProvider('directiveInjectionProvider')]
    public function testDirectiveInjectionIsBlocked(string $attempt): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        new CspDirectives(defaultSrc: $attempt);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function directiveInjectionProvider(): iterable
    {
        yield 'semicolon space' => ["'self'; script-src 'unsafe-inline'"];
        yield 'semicolon no space' => ["'self';script-src 'unsafe-eval'"];
        yield 'space semicolon space' => ["'self' ; report-uri https://evil.com"];
        yield 'none semicolon' => ["'none';base-uri https://evil.com"];
    }

    /**
     * Property: Unicode whitespace is rejected
     *
     * Non-ASCII whitespace could cause parser inconsistencies.
     */
    #[DataProvider('unicodeWhitespaceProvider')]
    public function testUnicodeWhitespaceIsRejected(string $char): void
    {
        $value = "'self'" . $char . 'https://example.com';

        $this->expectException(InvalidDirectiveValueException::class);
        new CspDirectives(defaultSrc: $value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unicodeWhitespaceProvider(): iterable
    {
        yield 'non-breaking space U+00A0' => ["\u{00A0}"];
        yield 'en quad U+2000' => ["\u{2000}"];
        yield 'em quad U+2001' => ["\u{2001}"];
        yield 'en space U+2002' => ["\u{2002}"];
        yield 'em space U+2003' => ["\u{2003}"];
        yield 'three-per-em space U+2004' => ["\u{2004}"];
        yield 'four-per-em space U+2005' => ["\u{2005}"];
        yield 'six-per-em space U+2006' => ["\u{2006}"];
        yield 'figure space U+2007' => ["\u{2007}"];
        yield 'punctuation space U+2008' => ["\u{2008}"];
        yield 'thin space U+2009' => ["\u{2009}"];
        yield 'hair space U+200A' => ["\u{200A}"];
        yield 'narrow no-break space U+202F' => ["\u{202F}"];
        yield 'medium mathematical space U+205F' => ["\u{205F}"];
        yield 'ideographic space U+3000' => ["\u{3000}"];
    }

    /**
     * Property: Valid header values produce parseable CSP headers
     *
     * Valid directive values should produce headers that don't contain
     * injection artifacts.
     */
    public function testValidValuesProduceSafeHeaders(): void
    {
        $validValues = [
            "'self'",
            "'self' https://example.com",
            "'self' https://*.example.com",
            "'none'",
            'https://cdn.example.com https://api.example.com',
        ];

        foreach ($validValues as $value) {
            $directives = CspDirectives::strict()->withImgSrc($value);
            $header     = HeaderBuilder::build($directives, new NullNonce());

            // Header should not contain injection artifacts
            $this->assertStringNotContainsString("\r", $header);
            $this->assertStringNotContainsString("\n", $header);
            $this->assertStringNotContainsString("\x00", $header);

            // Should have proper directive structure
            $this->assertStringContainsString('img-src', $header);
            $this->assertStringContainsString($value, $header);
        }
    }

    /**
     * Property: ResourceDirectives validation is consistent
     */
    public function testResourceDirectivesValidation(): void
    {
        $this->forAll(
            Generators::string()
        )->then(function (string $value): void {
            // Skip safe values
            if (
                !str_contains($value, ';')
                && preg_match('/[\x00-\x1F]/', $value) !== 1
                && preg_match('/[\x{00A0}\x{2000}-\x{200A}\x{202F}\x{205F}\x{3000}]/u', $value) !== 1
            ) {
                return;
            }

            // Value with injection chars should be rejected in all resource directives
            $methods = ['withImg', 'withFont', 'withConnect', 'withMedia', 'withWorker', 'withChild', 'withManifest'];

            foreach ($methods as $method) {
                $this->assertThrowsInvalidDirective(fn() => (new ResourceDirectives())->$method($value));
            }
        });
    }

    /**
     * Property: NavigationDirectives validation is consistent
     */
    #[DataProvider('navigationMethodProvider')]
    public function testNavigationDirectivesValidation(string $method): void
    {
        $injectionValue = "'self'; script-src 'unsafe-inline'";

        $this->expectException(InvalidDirectiveValueException::class);
        (new NavigationDirectives())->$method($injectionValue);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function navigationMethodProvider(): iterable
    {
        yield 'withFrameAncestors' => ['withFrameAncestors'];
        yield 'withBaseUri' => ['withBaseUri'];
        yield 'withFormAction' => ['withFormAction'];
    }

    /**
     * Property: ReportingConfig validates URIs
     */
    #[DataProvider('reportingInjectionProvider')]
    public function testReportingConfigValidation(string $attempt): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        new ReportingConfig(uri: $attempt);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function reportingInjectionProvider(): iterable
    {
        yield 'crlf injection' => ["https://report.example.com\r\nX-Injected: yes"];
        yield 'semicolon injection' => ["/csp-report;script-src 'unsafe-inline'"];
    }

    /**
     * Property: Generated headers are single-line
     *
     * CSP headers must be single-line to prevent HTTP response splitting.
     */
    public function testGeneratedHeadersAreSingleLine(): void
    {
        $configs = [
            CspDirectives::strict(),
            CspDirectives::development(),
            CspDirectives::legacy(),
            CspDirectives::strict()
                ->withImgSrc("'self' https://cdn.example.com")
                ->withFontSrc("'self' https://fonts.gstatic.com")
                ->withReportUri('/csp-violations'),
        ];

        foreach ($configs as $config) {
            $header = HeaderBuilder::build($config, new NullNonce());

            $this->assertStringNotContainsString("\r", $header, 'Header contains CR');
            $this->assertStringNotContainsString("\n", $header, 'Header contains LF');

            // Count semicolons - should only be directive separators
            $semicolonCount = substr_count($header, ';');
            $directiveCount = preg_match_all('/[a-z]+-[a-z]+/', $header);

            // Each directive separator is a semicolon, but the count relationship
            // is valid if semicolons < directives (last directive has no trailing semicolon)
            $this->assertLessThanOrEqual(
                $directiveCount,
                $semicolonCount,
                'More semicolons than expected for directive count'
            );
        }
    }

    /**
     * Helper to assert InvalidDirectiveValueException is thrown
     *
     * Uses callable to work around PHPStan's strict exception checking.
     */
    private function assertThrowsInvalidDirective(callable $callback): void
    {
        try {
            $callback();
            $this->fail('Expected InvalidDirectiveValueException was not thrown');
        } catch (InvalidDirectiveValueException) {
            $this->assertTrue(true);
        }
    }
}
