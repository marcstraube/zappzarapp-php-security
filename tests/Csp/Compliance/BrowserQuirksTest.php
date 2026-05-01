<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Compliance;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\NavigationDirectives;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;
use Zappzarapp\Security\Csp\SecurityPolicy;

/**
 * Browser Quirks and Edge Cases Tests
 *
 * Documents known browser-specific behaviors and edge cases in CSP handling.
 * These tests ensure the library generates headers that work correctly across browsers.
 */
final class BrowserQuirksTest extends TestCase
{
    private const string NONCE = 'test-nonce-value';

    // =========================================================================
    // Safari: data: URL Handling
    // =========================================================================

    #[Test]
    public function testDataUrlInImgSrcForSafariCompatibility(): void
    {
        // Safari requires explicit 'data:' for base64-encoded images
        // Default img-src includes data: for common patterns
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("img-src 'self' data:", $header);
    }

    // =========================================================================
    // Firefox: frame-ancestors vs X-Frame-Options
    // =========================================================================

    #[Test]
    public function testFrameAncestorsIncluded(): void
    {
        // Firefox prefers frame-ancestors over X-Frame-Options
        // Both should be set for maximum compatibility
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('frame-ancestors', $header);
    }

    #[Test]
    public function testFrameAncestorsDefaultsToSelf(): void
    {
        // Default is 'self' to prevent clickjacking
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertMatchesRegularExpression("/frame-ancestors 'self'/", $header);
    }

    // =========================================================================
    // Chrome: strict-dynamic Behavior
    // =========================================================================

    #[Test]
    public function testStrictDynamicWithNonceForChrome(): void
    {
        // Chrome requires nonce for strict-dynamic to work
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Both nonce and strict-dynamic must be present
        $this->assertMatchesRegularExpression("/script-src[^;]*'nonce-[^']+'/", $header);
        $this->assertStringContainsString("'strict-dynamic'", $header);
    }

    #[Test]
    public function testStrictDynamicIgnoresHostAllowlist(): void
    {
        // When strict-dynamic is present, host-based allowlists are ignored
        // Library includes 'self' as fallback for non-strict-dynamic browsers
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // 'self' is included but will be ignored by strict-dynamic browsers
        $this->assertMatchesRegularExpression("/script-src[^;]*'self'/", $header);
        $this->assertStringContainsString("'strict-dynamic'", $header);
    }

    // =========================================================================
    // Edge Legacy: base-uri Requirement
    // =========================================================================

    #[Test]
    public function testBaseUriIncludedForEdgeLegacy(): void
    {
        // Older Edge required base-uri to prevent base tag injection
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('base-uri', $header);
    }

    #[Test]
    public function testBaseUriDefaultsToSelf(): void
    {
        // Default to 'self' to prevent base tag injection attacks
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertMatchesRegularExpression("/base-uri 'self'/", $header);
    }

    // =========================================================================
    // WebSocket Connection Handling
    // =========================================================================

    #[Test]
    public function testWebSocketRequiresBothWssAndHttps(): void
    {
        // Some browsers require both wss: and https: for WebSocket
        // The https: is for the initial WebSocket handshake
        $directives = CspDirectives::development('localhost:5173');

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('wss://localhost:5173', $header);
        $this->assertStringContainsString('https://localhost:5173', $header);
    }

    #[Test]
    public function testWebSocketHostInConnectSrc(): void
    {
        // WebSocket hosts must be in connect-src
        $directives = CspDirectives::development('localhost:5173');

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertMatchesRegularExpression('/connect-src[^;]*wss:\/\/localhost:5173/', $header);
    }

    // =========================================================================
    // Empty Directive Edge Cases
    // =========================================================================

    #[Test]
    public function testEmptyResourceDoesNotCreateEmptyDirective(): void
    {
        // Empty directives should not appear in the header
        $resources = new ResourceDirectives(
            img: "'self'",
            media: '' // Empty
        );
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        // Should not have "media-src ;" or "media-src  "
        $this->assertStringNotContainsString('media-src ;', $header);
        $this->assertStringNotContainsString('media-src  ', $header);
    }

    // =========================================================================
    // Nonce Edge Cases
    // =========================================================================

    #[Test]
    public function testEmptyNonceOmitsNonceFromHeader(): void
    {
        // When nonce is empty, don't include it in the header
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue('');

        $this->assertStringNotContainsString("'nonce-'", $header);
    }

    #[Test]
    public function testEmptyNonceOmitsStrictDynamic(): void
    {
        // strict-dynamic requires a nonce to function
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue('');

        $this->assertStringNotContainsString("'strict-dynamic'", $header);
    }

    // =========================================================================
    // object-src Security
    // =========================================================================

    #[Test]
    public function testObjectSrcAlwaysNoneForFlashProtection(): void
    {
        // Flash and other plugins are security risks
        // object-src should always be 'none'
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("object-src 'none'", $header);
    }

    // =========================================================================
    // Form Action Security
    // =========================================================================

    #[Test]
    public function testFormActionDefaultsToSelf(): void
    {
        // form-action prevents form submissions to external sites
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertMatchesRegularExpression("/form-action 'self'/", $header);
    }

    #[Test]
    public function testFormActionCanBeCustomized(): void
    {
        // Allow form submissions to specific domains
        $navigation = new NavigationDirectives(
            formAction: "'self' https://payment.example.com"
        );
        $directives = new CspDirectives(navigation: $navigation);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("form-action 'self' https://payment.example.com", $header);
    }

    // =========================================================================
    // HTTPS Upgrade
    // =========================================================================

    #[Test]
    public function testUpgradeInsecureRequestsDefaultsToTrue(): void
    {
        // upgrade-insecure-requests should be enabled by default
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('upgrade-insecure-requests', $header);
    }

    #[Test]
    public function testUpgradeInsecureRequestsCanBeDisabled(): void
    {
        // Can be disabled for mixed-content testing
        $directives = CspDirectives::strict()->withUpgradeInsecure(false);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringNotContainsString('upgrade-insecure-requests', $header);
    }

    // =========================================================================
    // Style-src in Lenient Mode
    // =========================================================================

    #[Test]
    public function testLenientModeUsesUnsafeInlineForStyles(): void
    {
        // LENIENT mode allows inline styles for development
        $directives = new CspDirectives(securityPolicy: SecurityPolicy::LENIENT);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertMatchesRegularExpression("/style-src[^;]*'unsafe-inline'/", $header);
    }

    // =========================================================================
    // Case Sensitivity
    // =========================================================================

    #[Test]
    public function testDirectiveNamesAreLowerCase(): void
    {
        // Directive names must be lowercase
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Should not contain uppercase directive names
        $this->assertStringNotContainsString('Default-src', $header);
        $this->assertStringNotContainsString('DEFAULT-SRC', $header);
        $this->assertStringNotContainsString('Script-src', $header);
    }

    #[Test]
    public function testKeywordsAreLowerCase(): void
    {
        // CSP keywords must be lowercase
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringNotContainsString("'Self'", $header);
        $this->assertStringNotContainsString("'SELF'", $header);
        $this->assertStringNotContainsString("'Nonce-", $header);
    }
}
