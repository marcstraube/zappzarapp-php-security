<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Compliance;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\ReportingConfig;
use Zappzarapp\Security\Csp\HeaderBuilder;

/**
 * CSP Header Format Compliance Tests
 *
 * Tests that CSP headers conform to HTTP header syntax requirements.
 *
 * @see RFC 7230 (HTTP/1.1 Message Syntax)
 * @see RFC 7762 (CSP)
 */
final class CspHeaderFormatTest extends TestCase
{
    private const string NONCE = 'test-nonce-value';

    // =========================================================================
    // Header Name Tests
    // =========================================================================

    #[Test]
    public function testHeaderNameIsCorrect(): void
    {
        $this->assertSame('Content-Security-Policy', HeaderBuilder::HEADER_CSP);
    }

    #[Test]
    public function testReportOnlyHeaderNameIsCorrect(): void
    {
        $this->assertSame('Content-Security-Policy-Report-Only', HeaderBuilder::HEADER_CSP_REPORT_ONLY);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testBuildHeaderIncludesHeaderName(): void
    {
        $directives = CspDirectives::strict();

        $header = HeaderBuilder::buildHeader($directives);

        $this->assertStringStartsWith('Content-Security-Policy:', $header);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testBuildReportOnlyHeaderIncludesHeaderName(): void
    {
        $directives = CspDirectives::strict();

        $header = HeaderBuilder::buildReportOnlyHeader($directives);

        $this->assertStringStartsWith('Content-Security-Policy-Report-Only:', $header);
    }

    // =========================================================================
    // Directive Separator Tests
    // =========================================================================

    #[Test]
    public function testDirectivesSeparatedBySemicolonSpace(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Directives must be separated by "; " (semicolon + space)
        $this->assertStringContainsString('; ', $header);
    }

    #[Test]
    public function testNoTrailingSemicolon(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Header should not end with semicolon
        $this->assertStringEndsNotWith(';', $header);
        $this->assertStringEndsNotWith('; ', $header);
    }

    #[Test]
    public function testNoLeadingSemicolon(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Header should not start with semicolon
        $this->assertStringStartsNotWith(';', $header);
    }

    #[Test]
    public function testNoDoubleSemicolons(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Should never have consecutive semicolons
        $this->assertStringNotContainsString(';;', $header);
    }

    // =========================================================================
    // Source Value Separator Tests
    // =========================================================================

    #[Test]
    public function testSourceValuesSeparatedBySpace(): void
    {
        $directives = new CspDirectives(
            defaultSrc: "'self' https://cdn.example.com https://api.example.com"
        );

        $header = $directives->toHeaderValue(self::NONCE);

        // Multiple source values in a directive are space-separated
        $this->assertStringContainsString("'self' https://cdn.example.com https://api.example.com", $header);
    }

    #[Test]
    public function testDirectiveNameAndValueSeparatedBySpace(): void
    {
        $directives = new CspDirectives(defaultSrc: "'self'");

        $header = $directives->toHeaderValue(self::NONCE);

        // Directive name and value separated by single space
        $this->assertStringContainsString("default-src 'self'", $header);
    }

    // =========================================================================
    // No Injection Characters Tests
    // =========================================================================

    #[Test]
    public function testHeaderContainsNoNewlines(): void
    {
        $directives = CspDirectives::strict()
            ->withReportUri('/csp-violations')
            ->withReportTo('csp-endpoint');

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringNotContainsString("\n", $header);
        $this->assertStringNotContainsString("\r", $header);
    }

    #[Test]
    public function testHeaderContainsNoInternalSemicolonsInValues(): void
    {
        // Semicolons should only appear as directive separators
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Each semicolon should be followed by space and a directive name
        $parts = explode('; ', $header);
        foreach ($parts as $part) {
            // Each part should be a valid directive (name value)
            $this->assertMatchesRegularExpression('/^[a-z-]+(\s|$)/', $part);
        }
    }

    // =========================================================================
    // ASCII Character Tests
    // =========================================================================

    #[Test]
    public function testHeaderContainsOnlyAsciiCharacters(): void
    {
        $directives = CspDirectives::strict()
            ->withReportUri('/csp-violations')
            ->withReportTo('csp-endpoint');

        $header = $directives->toHeaderValue(self::NONCE);

        // HTTP headers must be ASCII
        $this->assertMatchesRegularExpression('/^[\x20-\x7E]+$/', $header);
    }

    // =========================================================================
    // Directive Order Tests (Informational)
    // =========================================================================

    #[Test]
    public function testDefaultSrcComesFirst(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // default-src should be first for readability
        $this->assertStringStartsWith('default-src', $header);
    }

    #[Test]
    public function testReportingDirectivesComeLast(): void
    {
        $reporting  = new ReportingConfig(uri: '/csp', endpoint: 'csp');
        $directives = new CspDirectives(reporting: $reporting);

        $header = $directives->toHeaderValue(self::NONCE);

        // report-uri and report-to should be at the end
        $parts       = explode('; ', $header);
        $lastTwo     = array_slice($parts, -2);
        $lastTwoText = implode(' ', $lastTwo);

        $this->assertStringContainsString('report', $lastTwoText);
    }

    // =========================================================================
    // Valueless Directive Tests
    // =========================================================================

    #[Test]
    public function testUpgradeInsecureRequestsHasNoValue(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // upgrade-insecure-requests is a valueless directive
        $this->assertStringContainsString('upgrade-insecure-requests', $header);
        // Should not be followed by a value
        $this->assertStringNotContainsString('upgrade-insecure-requests ', $header);
    }
}
