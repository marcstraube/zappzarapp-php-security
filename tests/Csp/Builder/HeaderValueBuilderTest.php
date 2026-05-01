<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Builder;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Builder\HeaderValueBuilder;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\NavigationDirectives;
use Zappzarapp\Security\Csp\Directive\ReportingConfig;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;
use Zappzarapp\Security\Csp\SecurityPolicy;

#[CoversClass(HeaderValueBuilder::class)]
#[UsesClass(CspDirectives::class)]
#[UsesClass(NavigationDirectives::class)]
#[UsesClass(ReportingConfig::class)]
#[UsesClass(ResourceDirectives::class)]
#[UsesClass(SecurityPolicy::class)]
final class HeaderValueBuilderTest extends TestCase
{
    private const string TEST_NONCE = 'test-nonce-value';

    // Basic Build Tests
    #[Test]
    public function testBuildReturnsString(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), self::TEST_NONCE);

        $result = $builder->build();

        $this->assertIsString($result);
        $this->assertNotEmpty($result);
    }

    #[Test]
    public function testBuildIncludesDefaultSrc(): void
    {
        $directives = new CspDirectives(defaultSrc: "'self' https://example.com");
        $builder    = new HeaderValueBuilder($directives, self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString("default-src 'self' https://example.com", $result);
    }

    // Script-src Build Tests
    #[Test]
    public function testBuildScriptSrcIncludesNonce(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString("'nonce-test-nonce-value'", $result);
    }

    #[Test]
    public function testBuildScriptSrcIncludesStrictDynamic(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString("'strict-dynamic'", $result);
    }

    #[Test]
    public function testBuildScriptSrcIncludesUnsafeEvalWhenAllowed(): void
    {
        $directives = new CspDirectives(securityPolicy: SecurityPolicy::UNSAFE_EVAL);
        $builder    = new HeaderValueBuilder($directives, self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString("'unsafe-eval'", $result);
    }

    #[Test]
    public function testBuildScriptSrcExcludesUnsafeEvalWhenStrict(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringNotContainsString("'unsafe-eval'", $result);
    }

    #[Test]
    public function testBuildWithCustomScriptSrcPrependsNonce(): void
    {
        $directives = new CspDirectives(scriptSrc: "'self' https://scripts.example.com");
        $builder    = new HeaderValueBuilder($directives, self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString("script-src 'nonce-test-nonce-value' 'self' https://scripts.example.com", $result);
    }

    #[Test]
    public function testBuildWithCustomScriptSrcContainingNonceKeepsAsIs(): void
    {
        $directives = new CspDirectives(scriptSrc: "'nonce-existing' 'self'");
        $builder    = new HeaderValueBuilder($directives, self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString("script-src 'nonce-existing' 'self'", $result);
        // Nonce should not be prepended to script-src when it already contains a nonce
        $this->assertStringNotContainsString("script-src 'nonce-test-nonce-value'", $result);
    }

    // Style-src Build Tests
    #[Test]
    public function testBuildStyleSrcIncludesNonceWhenStrict(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), self::TEST_NONCE);

        $result = $builder->build();

        $this->assertMatchesRegularExpression("/style-src '[^']+' 'nonce-test-nonce-value'/", $result);
    }

    #[Test]
    public function testBuildStyleSrcIncludesUnsafeInlineWhenLenient(): void
    {
        $directives = new CspDirectives(securityPolicy: SecurityPolicy::LENIENT);
        $builder    = new HeaderValueBuilder($directives, self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString("style-src 'self' 'unsafe-inline'", $result);
    }

    // Connect-src Build Tests
    #[Test]
    public function testBuildConnectSrcWithoutWebSocket(): void
    {
        $directives = new CspDirectives();
        $builder    = new HeaderValueBuilder($directives, self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString("connect-src 'self'", $result);
        $this->assertStringNotContainsString('wss://', $result);
    }

    #[Test]
    public function testBuildConnectSrcWithWebSocket(): void
    {
        $directives = new CspDirectives(websocketHost: 'localhost:5173');
        $builder    = new HeaderValueBuilder($directives, self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString("connect-src 'self' wss://localhost:5173 https://localhost:5173", $result);
    }

    // Empty Nonce Tests
    #[Test]
    public function testBuildWithEmptyNonceOmitsNonceFromScriptSrc(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), '');

        $result = $builder->build();

        $this->assertStringNotContainsString('nonce-', $result);
        $this->assertStringNotContainsString("'strict-dynamic'", $result);
    }

    #[Test]
    public function testBuildWithEmptyNonceOmitsNonceFromStyleSrc(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), '');

        $result = $builder->build();

        $this->assertStringContainsString("style-src 'self'", $result);
    }

    // Reporting Tests
    #[Test]
    public function testBuildIncludesUpgradeInsecureRequests(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString('upgrade-insecure-requests', $result);
    }

    #[Test]
    public function testBuildExcludesUpgradeInsecureRequestsWhenDisabled(): void
    {
        $directives = CspDirectives::strict()->withUpgradeInsecure(false);
        $builder    = new HeaderValueBuilder($directives, self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringNotContainsString('upgrade-insecure-requests', $result);
    }

    #[Test]
    public function testBuildIncludesReportUri(): void
    {
        $directives = CspDirectives::strict()->withReportUri('/csp-violations');
        $builder    = new HeaderValueBuilder($directives, self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString('report-uri /csp-violations', $result);
    }

    #[Test]
    public function testBuildIncludesReportTo(): void
    {
        $directives = CspDirectives::strict()->withReportTo('csp-endpoint');
        $builder    = new HeaderValueBuilder($directives, self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString('report-to csp-endpoint', $result);
    }

    // Object-src Tests
    #[Test]
    public function testBuildAlwaysIncludesObjectSrcNone(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString("object-src 'none'", $result);
    }

    // Resource Directives Tests
    #[Test]
    public function testBuildIncludesAllResourceDirectives(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString('img-src', $result);
        $this->assertStringContainsString('font-src', $result);
        $this->assertStringContainsString('connect-src', $result);
        $this->assertStringContainsString('media-src', $result);
        $this->assertStringContainsString('worker-src', $result);
        $this->assertStringContainsString('child-src', $result);
        $this->assertStringContainsString('frame-src', $result);
        $this->assertStringContainsString('manifest-src', $result);
    }

    // Navigation Directives Tests
    #[Test]
    public function testBuildIncludesAllNavigationDirectives(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString('frame-ancestors', $result);
        $this->assertStringContainsString('base-uri', $result);
        $this->assertStringContainsString('form-action', $result);
    }

    // Format Tests
    #[Test]
    public function testBuildSeparatesDirectivesWithSemicolonSpace(): void
    {
        $builder = new HeaderValueBuilder(CspDirectives::strict(), self::TEST_NONCE);

        $result = $builder->build();

        $this->assertStringContainsString('; ', $result);
        $this->assertStringNotContainsString(';;', $result);
    }
}
