<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Compliance;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\NavigationDirectives;
use Zappzarapp\Security\Csp\Directive\ReportingConfig;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;

/**
 * W3C CSP Level 3 Directive Names Compliance Tests
 *
 * Validates that all CSP directive names match the W3C specification.
 *
 * @see https://www.w3.org/TR/CSP3/
 */
final class W3cDirectiveNamesTest extends TestCase
{
    private const string NONCE = 'test-nonce';

    // =========================================================================
    // Fetch Directives (W3C CSP3 Section 6.1)
    // =========================================================================

    #[Test]
    public function testDefaultSrcDirective(): void
    {
        $directives = new CspDirectives(defaultSrc: "'self'");

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('default-src', $header);
    }

    #[Test]
    public function testScriptSrcDirective(): void
    {
        $directives = new CspDirectives(scriptSrc: "'self'");

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('script-src', $header);
    }

    #[Test]
    public function testStyleSrcDirective(): void
    {
        $directives = new CspDirectives(styleSrc: "'self'");

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('style-src', $header);
    }

    #[Test]
    public function testImgSrcDirective(): void
    {
        $resources  = new ResourceDirectives(img: "'self'");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('img-src', $header);
    }

    #[Test]
    public function testFontSrcDirective(): void
    {
        $resources  = new ResourceDirectives(font: "'self'");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('font-src', $header);
    }

    #[Test]
    public function testConnectSrcDirective(): void
    {
        $resources  = new ResourceDirectives(connect: "'self'");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('connect-src', $header);
    }

    #[Test]
    public function testMediaSrcDirective(): void
    {
        $resources  = new ResourceDirectives(media: "'self'");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('media-src', $header);
    }

    #[Test]
    public function testObjectSrcDirective(): void
    {
        $directives = new CspDirectives();

        $header = $directives->toHeaderValue(self::NONCE);

        // object-src is always 'none' by default for security
        $this->assertStringContainsString("object-src 'none'", $header);
    }

    #[Test]
    public function testFrameSrcDirective(): void
    {
        $resources  = new ResourceDirectives(frame: "'self'");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('frame-src', $header);
    }

    #[Test]
    public function testChildSrcDirective(): void
    {
        $resources  = new ResourceDirectives(child: "'self'");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('child-src', $header);
    }

    #[Test]
    public function testWorkerSrcDirective(): void
    {
        $resources  = new ResourceDirectives(worker: "'self'");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('worker-src', $header);
    }

    #[Test]
    public function testManifestSrcDirective(): void
    {
        $resources  = new ResourceDirectives(manifest: "'self'");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('manifest-src', $header);
    }

    // =========================================================================
    // Document Directives (W3C CSP3 Section 6.2)
    // =========================================================================

    #[Test]
    public function testBaseUriDirective(): void
    {
        $navigation = new NavigationDirectives(baseUri: "'self'");
        $directives = new CspDirectives(navigation: $navigation);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('base-uri', $header);
    }

    // =========================================================================
    // Navigation Directives (W3C CSP3 Section 6.3)
    // =========================================================================

    #[Test]
    public function testFormActionDirective(): void
    {
        $navigation = new NavigationDirectives(formAction: "'self'");
        $directives = new CspDirectives(navigation: $navigation);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('form-action', $header);
    }

    #[Test]
    public function testFrameAncestorsDirective(): void
    {
        $navigation = new NavigationDirectives(frameAncestors: "'self'");
        $directives = new CspDirectives(navigation: $navigation);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('frame-ancestors', $header);
    }

    // =========================================================================
    // Reporting Directives (W3C CSP3 Section 6.4)
    // =========================================================================

    #[Test]
    public function testReportUriDirective(): void
    {
        $reporting  = new ReportingConfig(uri: '/csp-violations');
        $directives = new CspDirectives(reporting: $reporting);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('report-uri', $header);
    }

    #[Test]
    public function testReportToDirective(): void
    {
        $reporting  = new ReportingConfig(endpoint: 'csp-endpoint');
        $directives = new CspDirectives(reporting: $reporting);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('report-to', $header);
    }

    // =========================================================================
    // Security Directives
    // =========================================================================

    #[Test]
    public function testUpgradeInsecureRequestsDirective(): void
    {
        $reporting  = new ReportingConfig(upgradeInsecure: true);
        $directives = new CspDirectives(reporting: $reporting);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('upgrade-insecure-requests', $header);
    }

    // =========================================================================
    // Directive Name Format Tests
    // =========================================================================

    #[DataProvider('directiveNameProvider')]
    #[Test]
    public function testDirectiveNamesAreLowerCaseWithHyphens(string $directiveName): void
    {
        // CSP directive names must be lowercase ASCII with hyphens
        $this->assertMatchesRegularExpression(
            '/^[a-z][a-z-]*[a-z]$/',
            $directiveName,
            "Directive name '$directiveName' must be lowercase with hyphens"
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function directiveNameProvider(): array
    {
        return [
            'default-src'               => ['default-src'],
            'script-src'                => ['script-src'],
            'style-src'                 => ['style-src'],
            'img-src'                   => ['img-src'],
            'font-src'                  => ['font-src'],
            'connect-src'               => ['connect-src'],
            'media-src'                 => ['media-src'],
            'object-src'                => ['object-src'],
            'frame-src'                 => ['frame-src'],
            'child-src'                 => ['child-src'],
            'worker-src'                => ['worker-src'],
            'manifest-src'              => ['manifest-src'],
            'base-uri'                  => ['base-uri'],
            'form-action'               => ['form-action'],
            'frame-ancestors'           => ['frame-ancestors'],
            'report-uri'                => ['report-uri'],
            'report-to'                 => ['report-to'],
            'upgrade-insecure-requests' => ['upgrade-insecure-requests'],
        ];
    }
}
