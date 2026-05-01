<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\Analyzer;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Analyzer\AnalysisResult;
use Zappzarapp\Security\Headers\Analyzer\Finding;
use Zappzarapp\Security\Headers\Analyzer\FindingSeverity;
use Zappzarapp\Security\Headers\Analyzer\SecurityHeaderAnalyzer;

#[CoversClass(SecurityHeaderAnalyzer::class)]
#[CoversClass(AnalysisResult::class)]
#[CoversClass(Finding::class)]
#[UsesClass(FindingSeverity::class)]
final class SecurityHeaderAnalyzerTest extends TestCase
{
    private SecurityHeaderAnalyzer $analyzer;

    protected function setUp(): void
    {
        $this->analyzer = new SecurityHeaderAnalyzer();
    }

    // === Full Analysis ===

    #[Test]
    public function testEmptyHeadersReportsAllMissing(): void
    {
        $result = $this->analyzer->analyze([]);

        $this->assertFalse($result->isClean());
        $this->assertTrue($result->hasHighOrAbove());
        $this->assertGreaterThanOrEqual(9, $result->count());
    }

    #[Test]
    public function testStrictHeadersAreClean(): void
    {
        $result = $this->analyzer->analyze([
            'Strict-Transport-Security'    => 'max-age=63072000; includeSubDomains',
            'Content-Security-Policy'      => "default-src 'self'",
            'X-Frame-Options'              => 'DENY',
            'X-Content-Type-Options'       => 'nosniff',
            'Referrer-Policy'              => 'strict-origin-when-cross-origin',
            'Permissions-Policy'           => 'camera=(), microphone=()',
            'Cross-Origin-Opener-Policy'   => 'same-origin',
            'Cross-Origin-Embedder-Policy' => 'require-corp',
            'Cross-Origin-Resource-Policy' => 'same-origin',
        ]);

        $this->assertTrue($result->isClean());
        $this->assertSame(0, $result->count());
    }

    #[Test]
    public function testCaseInsensitiveHeaderMatching(): void
    {
        $result = $this->analyzer->analyze([
            'strict-transport-security'    => 'max-age=63072000; includeSubDomains',
            'content-security-policy'      => "default-src 'self'",
            'x-frame-options'              => 'DENY',
            'x-content-type-options'       => 'nosniff',
            'referrer-policy'              => 'strict-origin-when-cross-origin',
            'permissions-policy'           => 'camera=()',
            'cross-origin-opener-policy'   => 'same-origin',
            'cross-origin-embedder-policy' => 'require-corp',
            'cross-origin-resource-policy' => 'same-origin',
        ]);

        $this->assertTrue($result->isClean());
    }

    // === HSTS ===

    #[Test]
    public function testMissingHstsIsHigh(): void
    {
        $findings = $this->analyzeHeader('Strict-Transport-Security', null);

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::HIGH, $findings[0]->severity);
    }

    #[Test]
    public function testHstsLowMaxAge(): void
    {
        $findings = $this->analyzeHeader('Strict-Transport-Security', 'max-age=3600; includeSubDomains');

        $this->assertNotEmpty($findings);
        $this->assertSame(FindingSeverity::MEDIUM, $findings[0]->severity);
        $this->assertStringContainsString('3600', $findings[0]->message);
    }

    #[Test]
    public function testHstsMissingIncludeSubDomains(): void
    {
        $findings = $this->analyzeHeader('Strict-Transport-Security', 'max-age=63072000');

        $this->assertNotEmpty($findings);

        $finding = $this->findFindingWithMessage($findings, 'includeSubDomains');

        $this->assertNotNull($finding);
        $this->assertSame(FindingSeverity::MEDIUM, $finding->severity);
    }

    #[Test]
    public function testHstsLowMaxAgeAndMissingIncludeSubDomains(): void
    {
        $findings = $this->analyzeHeader('Strict-Transport-Security', 'max-age=3600');

        $this->assertCount(2, $findings);
    }

    #[Test]
    public function testHstsExactMinMaxAgeIsAccepted(): void
    {
        $findings = $this->analyzeHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

        $this->assertEmpty($findings);
    }

    #[Test]
    public function testHstsCaseInsensitiveMaxAge(): void
    {
        $findings = $this->analyzeHeader('Strict-Transport-Security', 'Max-Age=3600; includeSubDomains');

        $this->assertNotEmpty($findings);
        $this->assertStringContainsString('3600', $findings[0]->message);
    }

    #[Test]
    public function testHstsValidConfig(): void
    {
        $findings = $this->analyzeHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');

        $this->assertEmpty($findings);
    }

    // === CSP ===

    #[Test]
    public function testMissingCspIsHigh(): void
    {
        $findings = $this->analyzeHeader('Content-Security-Policy', null);

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::HIGH, $findings[0]->severity);
    }

    #[Test]
    public function testCspMissingDefaultSrc(): void
    {
        $findings = $this->analyzeHeader('Content-Security-Policy', "script-src 'self'");

        $finding = $this->findFindingWithMessage($findings, 'default-src');

        $this->assertNotNull($finding);
        $this->assertSame(FindingSeverity::MEDIUM, $finding->severity);
    }

    #[Test]
    public function testCspUnsafeInlineInScriptSrc(): void
    {
        $findings = $this->analyzeHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'");

        $finding = $this->findFindingWithMessage($findings, 'unsafe-inline');

        $this->assertNotNull($finding);
        $this->assertSame(FindingSeverity::HIGH, $finding->severity);
    }

    #[Test]
    public function testCspUnsafeEvalInScriptSrc(): void
    {
        $findings = $this->analyzeHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-eval'");

        $finding = $this->findFindingWithMessage($findings, 'unsafe-eval');

        $this->assertNotNull($finding);
        $this->assertSame(FindingSeverity::HIGH, $finding->severity);
    }

    #[Test]
    public function testCspUnsafeInlineInStyleSrcIsMedium(): void
    {
        $findings = $this->analyzeHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'");

        $finding = $this->findFindingWithMessage($findings, 'style-src');

        $this->assertNotNull($finding);
        $this->assertSame(FindingSeverity::MEDIUM, $finding->severity);
    }

    #[Test]
    public function testCspWildcardSource(): void
    {
        $findings = $this->analyzeHeader('Content-Security-Policy', "default-src *");

        $finding = $this->findFindingWithMessage($findings, 'wildcard');

        $this->assertNotNull($finding);
        $this->assertSame(FindingSeverity::HIGH, $finding->severity);
    }

    #[Test]
    public function testCspUnsafeInlineInStyleSrcFallsBackToDefaultSrc(): void
    {
        $findings = $this->analyzeHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline'; script-src 'self'");

        $styleFinding = $this->findFindingWithMessage($findings, 'style-src');

        $this->assertNotNull($styleFinding);
        $this->assertSame(FindingSeverity::MEDIUM, $styleFinding->severity);
    }

    #[Test]
    public function testCspUppercaseDirectiveNames(): void
    {
        $findings = $this->analyzeHeader('Content-Security-Policy', "DEFAULT-SRC 'self'; SCRIPT-SRC 'self' 'unsafe-inline'");

        $finding = $this->findFindingWithMessage($findings, 'unsafe-inline');

        $this->assertNotNull($finding);
    }

    #[Test]
    public function testCspValidPolicy(): void
    {
        $findings = $this->analyzeHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'");

        $this->assertEmpty($findings);
    }

    #[Test]
    public function testCspDirectiveSourcesAreCorrectlyParsed(): void
    {
        // script-src has 'self' but NOT 'unsafe-inline' — the directive name
        // must not leak into the sources
        $findings = $this->analyzeHeader(
            'Content-Security-Policy',
            "default-src 'none'; script-src 'self' https://cdn.example.com",
        );

        $unsafeFinding = $this->findFindingWithMessage($findings, 'unsafe-inline');

        $this->assertNull($unsafeFinding);
    }

    #[Test]
    public function testCspUnsafeInlineInheritedFromDefaultSrc(): void
    {
        $findings = $this->analyzeHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline'");

        $this->assertNotEmpty($findings);

        $finding = $this->findFindingWithMessage($findings, 'script-src');

        $this->assertNotNull($finding);
    }

    // === X-Frame-Options ===

    #[Test]
    public function testMissingXFrameOptionsIsMedium(): void
    {
        $findings = $this->analyzeHeader('X-Frame-Options', null);

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::MEDIUM, $findings[0]->severity);
    }

    #[Test]
    public function testXFrameOptionsDeny(): void
    {
        $findings = $this->analyzeHeader('X-Frame-Options', 'DENY');

        $this->assertEmpty($findings);
    }

    #[Test]
    public function testXFrameOptionsSameorigin(): void
    {
        $findings = $this->analyzeHeader('X-Frame-Options', 'SAMEORIGIN');

        $this->assertEmpty($findings);
    }

    // === X-Content-Type-Options ===

    #[Test]
    public function testMissingXContentTypeOptionsIsMedium(): void
    {
        $findings = $this->analyzeHeader('X-Content-Type-Options', null);

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::MEDIUM, $findings[0]->severity);
    }

    #[Test]
    public function testXContentTypeOptionsNosniff(): void
    {
        $findings = $this->analyzeHeader('X-Content-Type-Options', 'nosniff');

        $this->assertEmpty($findings);
    }

    #[Test]
    public function testXContentTypeOptionsNosniffCaseInsensitive(): void
    {
        $findings = $this->analyzeHeader('X-Content-Type-Options', ' Nosniff ');

        $this->assertEmpty($findings);
    }

    #[Test]
    public function testXContentTypeOptionsInvalidValue(): void
    {
        $findings = $this->analyzeHeader('X-Content-Type-Options', 'none');

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::MEDIUM, $findings[0]->severity);
    }

    // === Referrer-Policy ===

    #[Test]
    public function testMissingReferrerPolicyIsLow(): void
    {
        $findings = $this->analyzeHeader('Referrer-Policy', null);

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::LOW, $findings[0]->severity);
    }

    #[Test]
    public function testReferrerPolicyUnsafeUrlIsHigh(): void
    {
        $findings = $this->analyzeHeader('Referrer-Policy', 'unsafe-url');

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::HIGH, $findings[0]->severity);
    }

    #[Test]
    public function testReferrerPolicyNoReferrerWhenDowngradeIsLow(): void
    {
        $findings = $this->analyzeHeader('Referrer-Policy', 'no-referrer-when-downgrade');

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::LOW, $findings[0]->severity);
    }

    #[Test]
    public function testReferrerPolicyUnsafeUrlCaseInsensitive(): void
    {
        $findings = $this->analyzeHeader('Referrer-Policy', ' Unsafe-URL ');

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::HIGH, $findings[0]->severity);
    }

    #[Test]
    public function testReferrerPolicyStrictOriginWhenCrossOrigin(): void
    {
        $findings = $this->analyzeHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

        $this->assertEmpty($findings);
    }

    // === Permissions-Policy ===

    #[Test]
    public function testMissingPermissionsPolicyIsLow(): void
    {
        $findings = $this->analyzeHeader('Permissions-Policy', null);

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::LOW, $findings[0]->severity);
    }

    #[Test]
    public function testPermissionsPolicyPresent(): void
    {
        $findings = $this->analyzeHeader('Permissions-Policy', 'camera=(), microphone=()');

        $this->assertEmpty($findings);
    }

    // === COOP ===

    #[Test]
    public function testMissingCoopIsLow(): void
    {
        $findings = $this->analyzeHeader('Cross-Origin-Opener-Policy', null);

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::LOW, $findings[0]->severity);
    }

    // === COEP ===

    #[Test]
    public function testMissingCoepIsInfo(): void
    {
        $findings = $this->analyzeHeader('Cross-Origin-Embedder-Policy', null);

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::INFO, $findings[0]->severity);
    }

    // === CORP ===

    #[Test]
    public function testMissingCorpIsInfo(): void
    {
        $findings = $this->analyzeHeader('Cross-Origin-Resource-Policy', null);

        $this->assertCount(1, $findings);
        $this->assertSame(FindingSeverity::INFO, $findings[0]->severity);
    }

    // === AnalysisResult ===

    #[Test]
    public function testResultForHeaderFiltersCorrectly(): void
    {
        $result = $this->analyzer->analyze([]);

        $hstsFindings = $result->forHeader('Strict-Transport-Security');
        $cspFindings  = $result->forHeader('Content-Security-Policy');

        $this->assertCount(1, $hstsFindings);
        $this->assertCount(1, $cspFindings);
    }

    #[Test]
    public function testResultForHeaderIsCaseInsensitive(): void
    {
        $result = $this->analyzer->analyze([]);

        $this->assertCount(1, $result->forHeader('strict-transport-security'));
        $this->assertCount(1, $result->forHeader('STRICT-TRANSPORT-SECURITY'));
    }

    #[Test]
    public function testResultHasCritical(): void
    {
        $result = new AnalysisResult(
            new Finding('test', FindingSeverity::CRITICAL, 'msg', 'rec'),
        );

        $this->assertTrue($result->hasCritical());
        $this->assertTrue($result->hasHighOrAbove());
    }

    #[Test]
    public function testResultHasHighOrAbove(): void
    {
        $result = new AnalysisResult(
            new Finding('test', FindingSeverity::HIGH, 'msg', 'rec'),
        );

        $this->assertFalse($result->hasCritical());
        $this->assertTrue($result->hasHighOrAbove());
    }

    #[Test]
    public function testResultIsClean(): void
    {
        $result = new AnalysisResult();

        $this->assertTrue($result->isClean());
        $this->assertSame(0, $result->count());
    }

    #[Test]
    public function testFindingProperties(): void
    {
        $finding = new Finding('X-Frame-Options', FindingSeverity::HIGH, 'missing', 'add it');

        $this->assertSame('X-Frame-Options', $finding->header);
        $this->assertSame(FindingSeverity::HIGH, $finding->severity);
        $this->assertSame('missing', $finding->message);
        $this->assertSame('add it', $finding->recommendation);
    }

    // === Helpers ===

    /**
     * Analyze headers with all secure defaults except the given header
     *
     * @return list<Finding>
     */
    private function analyzeHeader(string $header, ?string $value): array
    {
        $secureDefaults = [
            'Strict-Transport-Security'    => 'max-age=63072000; includeSubDomains',
            'Content-Security-Policy'      => "default-src 'self'",
            'X-Frame-Options'              => 'DENY',
            'X-Content-Type-Options'       => 'nosniff',
            'Referrer-Policy'              => 'strict-origin-when-cross-origin',
            'Permissions-Policy'           => 'camera=()',
            'Cross-Origin-Opener-Policy'   => 'same-origin',
            'Cross-Origin-Embedder-Policy' => 'require-corp',
            'Cross-Origin-Resource-Policy' => 'same-origin',
        ];

        if ($value === null) {
            unset($secureDefaults[$header]);
        } else {
            $secureDefaults[$header] = $value;
        }

        $result = $this->analyzer->analyze($secureDefaults);

        return $result->forHeader($header);
    }

    /**
     * @param list<Finding> $findings
     */
    private function findFindingWithMessage(array $findings, string $substring): ?Finding
    {
        foreach ($findings as $finding) {
            if (str_contains(strtolower($finding->message), strtolower($substring))) {
                return $finding;
            }
        }

        return null;
    }
}
