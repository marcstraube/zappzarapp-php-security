<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Compliance;

use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;
use Zappzarapp\Security\Csp\SecurityPolicy;

/**
 * CSP Level 2/3 Compatibility Tests
 *
 * Documents differences between CSP Level 2 and Level 3, and how this library
 * handles backward compatibility.
 *
 * @see https://www.w3.org/TR/CSP2/
 * @see https://www.w3.org/TR/CSP3/
 */
final class Csp2Csp3CompatibilityTest extends TestCase
{
    private const string NONCE = 'test-nonce-value';

    // =========================================================================
    // CSP3: strict-dynamic
    // =========================================================================

    public function testStrictDynamicIsCsp3Feature(): void
    {
        // strict-dynamic is CSP Level 3 only
        // Older browsers (CSP2) will ignore it
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("'strict-dynamic'", $header);
    }

    public function testStrictDynamicIncludedWithNonce(): void
    {
        // strict-dynamic allows scripts loaded by trusted scripts
        // Requires nonce to identify trusted scripts
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("'nonce-" . self::NONCE . "'", $header);
        $this->assertStringContainsString("'strict-dynamic'", $header);
    }

    // =========================================================================
    // CSP2/3: Nonce Backward Compatibility
    // =========================================================================

    public function testNonceFormatCompatible(): void
    {
        // Nonce format is the same in CSP2 and CSP3
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Format: 'nonce-<value>' - value should be URL-safe characters
        $this->assertMatchesRegularExpression("/'nonce-[A-Za-z0-9+\\/=-]+'/", $header);
    }

    public function testScriptSrcIncludesSelfForCsp2Fallback(): void
    {
        // 'self' provides fallback for CSP2 browsers that don't support strict-dynamic
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertMatchesRegularExpression("/script-src[^;]*'self'/", $header);
    }

    // =========================================================================
    // CSP3: worker-src
    // =========================================================================

    public function testWorkerSrcIsCsp3Feature(): void
    {
        // worker-src was introduced in CSP3
        // CSP2 browsers fall back to child-src, then script-src
        $resources  = new ResourceDirectives(worker: "'self' blob:");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('worker-src', $header);
    }

    public function testChildSrcProvidesCsp2Fallback(): void
    {
        // child-src is CSP2, provides fallback for worker-src
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('child-src', $header);
    }

    // =========================================================================
    // CSP3: manifest-src
    // =========================================================================

    public function testManifestSrcIsCsp3Feature(): void
    {
        // manifest-src controls web app manifest loading (CSP3)
        $resources  = new ResourceDirectives(manifest: "'self'");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('manifest-src', $header);
    }

    // =========================================================================
    // CSP2/3: frame-src vs child-src
    // =========================================================================

    public function testFrameSrcAndChildSrcBothIncluded(): void
    {
        // CSP2 deprecated frame-src in favor of child-src
        // CSP3 brought back frame-src for frames, child-src for workers
        // Library includes both for maximum compatibility
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('frame-src', $header);
        $this->assertStringContainsString('child-src', $header);
    }

    // =========================================================================
    // CSP2/3: Reporting
    // =========================================================================

    public function testReportUriIsCsp2(): void
    {
        // report-uri is CSP2 (deprecated but widely supported)
        $directives = CspDirectives::strict()->withReportUri('/csp-violations');

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('report-uri', $header);
    }

    public function testReportToIsCsp3(): void
    {
        // report-to is CSP3 (uses Reporting API)
        $directives = CspDirectives::strict()->withReportTo('csp-endpoint');

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('report-to', $header);
    }

    public function testBothReportUriAndReportToCanBeUsed(): void
    {
        // For maximum compatibility, use both
        // CSP3 browsers prefer report-to
        // CSP2 browsers use report-uri
        $directives = CspDirectives::strict()
            ->withReportUri('/csp-violations')
            ->withReportTo('csp-endpoint');

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('report-uri /csp-violations', $header);
        $this->assertStringContainsString('report-to csp-endpoint', $header);
    }

    // =========================================================================
    // CSP2/3: unsafe-hashes (Not Implemented)
    // =========================================================================

    public function testUnsafeHashesNotImplemented(): void
    {
        // 'unsafe-hashes' is a CSP3 feature for event handlers
        // This library does not implement it (nonces are preferred)
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringNotContainsString('unsafe-hashes', $header);
    }

    // =========================================================================
    // Security Policy Levels
    // =========================================================================

    public function testStrictPolicyUsesModernCsp3Features(): void
    {
        $directives = new CspDirectives(securityPolicy: SecurityPolicy::STRICT);

        $header = $directives->toHeaderValue(self::NONCE);

        // STRICT uses nonce + strict-dynamic (CSP3)
        $this->assertStringContainsString('nonce-', $header);
        $this->assertStringContainsString("'strict-dynamic'", $header);
        // No unsafe-* directives
        $this->assertStringNotContainsString("'unsafe-inline'", $header);
        $this->assertStringNotContainsString("'unsafe-eval'", $header);
    }

    public function testLenientPolicyProvidesCsp2Fallback(): void
    {
        $directives = new CspDirectives(securityPolicy: SecurityPolicy::LENIENT);

        $header = $directives->toHeaderValue(self::NONCE);

        // LENIENT includes unsafe-inline for CSP2 compatibility
        $this->assertStringContainsString("'unsafe-inline'", $header);
        $this->assertStringContainsString("'unsafe-eval'", $header);
    }
}
