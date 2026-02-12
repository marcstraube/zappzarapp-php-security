<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\SecurityPolicy;

/**
 * Tests for CspDirectives factory methods
 */
final class CspDirectivesFactoryTest extends TestCase
{
    // strict()
    public function testStrictReturnsStrictPolicy(): void
    {
        $directives = CspDirectives::strict();

        $this->assertSame(SecurityPolicy::STRICT, $directives->securityPolicy);
    }

    public function testStrictHasNoWebSocket(): void
    {
        $directives = CspDirectives::strict();

        $this->assertNull($directives->websocketHost);
    }

    public function testStrictHeaderDisallowsUnsafeDirectives(): void
    {
        $directives = CspDirectives::strict();
        $header     = $directives->toHeaderValue('test-nonce');

        $this->assertStringNotContainsString("'unsafe-eval'", $header);
        $this->assertStringNotContainsString("'unsafe-inline'", $header);
    }

    public function testStrictIsChainable(): void
    {
        $directives = CspDirectives::strict()
            ->withImgSrc("'self' https://cdn.example.com")
            ->withReportUri('/csp-violations');

        $this->assertSame("'self' https://cdn.example.com", $directives->resources->img);
        $this->assertSame('/csp-violations', $directives->reporting->uri);
    }

    // development()
    public function testDevelopmentReturnsLenientPolicy(): void
    {
        $directives = CspDirectives::development();

        $this->assertSame(SecurityPolicy::LENIENT, $directives->securityPolicy);
    }

    public function testDevelopmentWithoutHotReload(): void
    {
        $directives = CspDirectives::development();

        $this->assertNull($directives->websocketHost);
    }

    public function testDevelopmentWithHotReload(): void
    {
        $directives = CspDirectives::development('localhost:5173');

        $this->assertSame('localhost:5173', $directives->websocketHost);
    }

    public function testDevelopmentHeaderAllowsUnsafeDirectives(): void
    {
        $directives = CspDirectives::development();
        $header     = $directives->toHeaderValue('test-nonce');

        $this->assertStringContainsString("'unsafe-eval'", $header);
        $this->assertStringContainsString("'unsafe-inline'", $header);
    }

    public function testDevelopmentHeaderIncludesWebSocket(): void
    {
        $directives = CspDirectives::development('localhost:5173');
        $header     = $directives->toHeaderValue('test-nonce');

        $this->assertStringContainsString('wss://localhost:5173', $header);
        $this->assertStringContainsString('https://localhost:5173', $header);
    }

    public function testDevelopmentWithCustomIp(): void
    {
        $directives = CspDirectives::development('192.168.1.100:8080');

        $this->assertSame('192.168.1.100:8080', $directives->websocketHost);
    }

    public function testDevelopmentIsChainable(): void
    {
        $directives = CspDirectives::development('localhost:5173')
            ->withImgSrc("'self' data:")
            ->withFontSrc("'self' https://fonts.gstatic.com");

        $this->assertSame("'self' data:", $directives->resources->img);
        $this->assertSame("'self' https://fonts.gstatic.com", $directives->resources->font);
        $this->assertSame('localhost:5173', $directives->websocketHost);
    }

    // legacy()
    public function testLegacyReturnsUnsafeEvalPolicy(): void
    {
        $directives = CspDirectives::legacy();

        $this->assertSame(SecurityPolicy::UNSAFE_EVAL, $directives->securityPolicy);
    }

    public function testLegacyHasNoWebSocket(): void
    {
        $directives = CspDirectives::legacy();

        $this->assertNull($directives->websocketHost);
    }

    public function testLegacyHeaderAllowsUnsafeEval(): void
    {
        $directives = CspDirectives::legacy();
        $header     = $directives->toHeaderValue('test-nonce');

        $this->assertStringContainsString("'unsafe-eval'", $header);
    }

    public function testLegacyHeaderDisallowsUnsafeInline(): void
    {
        $directives = CspDirectives::legacy();
        $header     = $directives->toHeaderValue('test-nonce');

        $this->assertStringNotContainsString("'unsafe-inline'", $header);
    }

    public function testLegacyIsChainable(): void
    {
        $directives = CspDirectives::legacy()
            ->withImgSrc("'self' data:")
            ->withFontSrc("'self' https://fonts.gstatic.com");

        $this->assertSame("'self' data:", $directives->resources->img);
        $this->assertSame("'self' https://fonts.gstatic.com", $directives->resources->font);
    }

    // Comparison
    public function testFactoryMethodsReturnDifferentPolicies(): void
    {
        $strict      = CspDirectives::strict();
        $development = CspDirectives::development();
        $legacy      = CspDirectives::legacy();

        $this->assertNotSame($strict->securityPolicy, $development->securityPolicy);
        $this->assertNotSame($strict->securityPolicy, $legacy->securityPolicy);
        $this->assertNotSame($development->securityPolicy, $legacy->securityPolicy);
    }

    public function testFactoryMethodsAreEquivalentToConstructor(): void
    {
        $strict1 = CspDirectives::strict();
        $strict2 = new CspDirectives(securityPolicy: SecurityPolicy::STRICT);

        $this->assertSame($strict1->securityPolicy, $strict2->securityPolicy);
        $this->assertSame($strict1->defaultSrc, $strict2->defaultSrc);
    }
}
