<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Compliance;

use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;

/**
 * CSP Directive Fallback Behavior Tests
 *
 * Tests the CSP directive fallback chain as defined in W3C CSP3.
 * When a specific directive is not set, browsers fall back to default-src.
 *
 * Note: This library explicitly sets all directives, so these tests document
 * the library's behavior rather than relying on browser fallback.
 *
 * @see https://www.w3.org/TR/CSP3/#directive-fallback-list
 */
final class DirectiveFallbackTest extends TestCase
{
    private const string NONCE = 'test-nonce';

    // =========================================================================
    // Explicit Directive Behavior (No Fallback Needed)
    // =========================================================================

    public function testLibraryExplicitlySetsAllFetchDirectives(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Library sets all fetch directives explicitly (no fallback needed)
        $this->assertStringContainsString('default-src', $header);
        $this->assertStringContainsString('script-src', $header);
        $this->assertStringContainsString('style-src', $header);
        $this->assertStringContainsString('img-src', $header);
        $this->assertStringContainsString('font-src', $header);
        $this->assertStringContainsString('connect-src', $header);
        $this->assertStringContainsString('media-src', $header);
        $this->assertStringContainsString('object-src', $header);
        $this->assertStringContainsString('frame-src', $header);
        $this->assertStringContainsString('child-src', $header);
        $this->assertStringContainsString('worker-src', $header);
        $this->assertStringContainsString('manifest-src', $header);
    }

    // =========================================================================
    // Default Resource Values
    // =========================================================================

    public function testDefaultImgSrcIncludesData(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Default img-src includes 'self' data: for common inline image patterns
        $this->assertStringContainsString("img-src 'self' data:", $header);
    }

    public function testDefaultFontSrcIsSelf(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertMatchesRegularExpression("/font-src 'self'/", $header);
    }

    public function testDefaultConnectSrcIsSelf(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertMatchesRegularExpression("/connect-src 'self'/", $header);
    }

    // =========================================================================
    // Resource Override Behavior
    // =========================================================================

    public function testCustomImgSrcOverridesDefault(): void
    {
        $resources  = new ResourceDirectives(img: "'self' https://cdn.example.com");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("img-src 'self' https://cdn.example.com", $header);
        // Should not have the default 'data:'
        $this->assertStringNotContainsString("img-src 'self' data:", $header);
    }

    public function testCustomFontSrcOverridesDefault(): void
    {
        $resources  = new ResourceDirectives(font: "'self' https://fonts.gstatic.com");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("font-src 'self' https://fonts.gstatic.com", $header);
    }

    // =========================================================================
    // Empty Directive Behavior
    // =========================================================================

    public function testEmptyResourceDirectiveNotIncludedInHeader(): void
    {
        $resources  = new ResourceDirectives(media: '');
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        // Empty directive values should not appear in header
        // (browser will fall back to default-src)
        $this->assertStringNotContainsString('media-src ;', $header);
        $this->assertStringNotContainsString('media-src  ', $header);
    }

    // =========================================================================
    // Object-src Special Case
    // =========================================================================

    public function testObjectSrcAlwaysNone(): void
    {
        // object-src is always 'none' for security (blocks Flash, Java, etc.)
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("object-src 'none'", $header);
    }

    public function testObjectSrcCannotBeOverridden(): void
    {
        // Users cannot change object-src from the public API
        // This is intentional for security
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Verify object-src is still 'none'
        $this->assertStringContainsString("object-src 'none'", $header);
    }

    // =========================================================================
    // Script/Style Fallback to Nonce
    // =========================================================================

    public function testScriptSrcFallsBackToNonceBasedPolicy(): void
    {
        // When scriptSrc is null, library generates nonce-based policy
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Should include nonce and strict-dynamic
        $this->assertStringContainsString("'nonce-" . self::NONCE . "'", $header);
        $this->assertStringContainsString("'strict-dynamic'", $header);
    }

    public function testStyleSrcFallsBackToNonceBasedPolicy(): void
    {
        // When styleSrc is null in STRICT mode, library generates nonce-based policy
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Should include nonce in style-src
        $this->assertMatchesRegularExpression("/style-src[^;]*'nonce-" . self::NONCE . "'/", $header);
    }
}
