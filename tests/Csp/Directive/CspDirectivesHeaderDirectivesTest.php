<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\NavigationDirectives;
use Zappzarapp\Security\Csp\Directive\ReportingConfig;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;
use Zappzarapp\Security\Csp\SecurityPolicy;

/**
 * Tests for CspDirectives::toHeaderValue() - WebSocket, Reporting, Resources, Navigation
 */
final class CspDirectivesHeaderDirectivesTest extends TestCase
{
    // WebSocket Support
    /**
     * @throws RandomException
     */
    #[Test]
    public function testIncludesWebSocketInConnectSrc(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $header    = (new CspDirectives())
            ->withWebSocket('api.example.com:443')
            ->toHeaderValue($nonce);

        $this->assertStringContainsString('wss://api.example.com:443', $header);
        $this->assertStringContainsString('https://api.example.com:443', $header);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testConnectSrcWithoutWebSocketReturnsOnlyBaseValue(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $header    = (new CspDirectives())->toHeaderValue($nonce);

        // Extract connect-src directive
        preg_match('/connect-src ([^;]+)/', $header, $matches);
        $connectSrc = $matches[1] ?? '';

        // Without websocket, connect-src should only contain the base value
        $this->assertSame("'self'", $connectSrc);
        $this->assertStringNotContainsString('wss://', $header);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testWebSocketHostAcceptsUppercaseHostname(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        // Uppercase hostname should be valid (case-insensitive regex)
        $header = (new CspDirectives())
            ->withWebSocket('LOCALHOST:5173')
            ->toHeaderValue($nonce);

        $this->assertStringContainsString('wss://LOCALHOST:5173', $header);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testWebSocketWithLenientPolicy(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();
        $header    = (new CspDirectives(
            websocketHost: 'localhost:8443',
            securityPolicy: SecurityPolicy::LENIENT,
        ))->toHeaderValue($nonce);

        $this->assertStringContainsString("'unsafe-eval'", $header);
        $this->assertStringContainsString("'unsafe-inline'", $header);
        $this->assertStringContainsString('wss://localhost:8443', $header);
    }

    // Upgrade Insecure Requests
    #[Test]
    public function testIncludesUpgradeInsecureRequestsByDefault(): void
    {
        $header = (new CspDirectives())->toHeaderValue('test-nonce');

        $this->assertStringContainsString('upgrade-insecure-requests', $header);
    }

    #[Test]
    public function testExcludesUpgradeInsecureRequestsWhenDisabled(): void
    {
        $reporting = new ReportingConfig(upgradeInsecure: false);
        $header    = (new CspDirectives(reporting: $reporting))->toHeaderValue('test-nonce');

        $this->assertStringNotContainsString('upgrade-insecure-requests', $header);
    }

    // Reporting Directives
    #[Test]
    public function testIncludesReportUri(): void
    {
        $reporting = new ReportingConfig(uri: '/csp-report');
        $header    = (new CspDirectives(reporting: $reporting))->toHeaderValue('test-nonce');

        $this->assertStringContainsString('report-uri /csp-report', $header);
    }

    #[Test]
    public function testIncludesReportTo(): void
    {
        $reporting = new ReportingConfig(endpoint: 'csp-endpoint');
        $header    = (new CspDirectives(reporting: $reporting))->toHeaderValue('test-nonce');

        $this->assertStringContainsString('report-to csp-endpoint', $header);
    }

    #[Test]
    public function testIncludesBothReportUriAndReportTo(): void
    {
        $reporting = new ReportingConfig(uri: '/csp-report', endpoint: 'csp-endpoint');
        $header    = (new CspDirectives(reporting: $reporting))->toHeaderValue('test-nonce');

        $this->assertStringContainsString('report-uri /csp-report', $header);
        $this->assertStringContainsString('report-to csp-endpoint', $header);
    }

    // Object-src Default
    #[Test]
    public function testAlwaysIncludesObjectSrcNone(): void
    {
        $header = (new CspDirectives())->toHeaderValue('test-nonce');

        $this->assertStringContainsString("object-src 'none'", $header);
    }

    // Sub-Value-Object Integration
    #[Test]
    public function testIncludesCustomResourceDirectives(): void
    {
        $customResources = new ResourceDirectives(
            img: "'self' https://images.cdn.com",
            font: "'self' https://fonts.cdn.com",
            connect: "'self' https://api.cdn.com"
        );

        $directives = (new CspDirectives())->withResources($customResources);
        $header     = $directives->toHeaderValue('test-nonce');

        $this->assertStringContainsString("img-src 'self' https://images.cdn.com", $header);
        $this->assertStringContainsString("font-src 'self' https://fonts.cdn.com", $header);
        $this->assertStringContainsString("connect-src 'self' https://api.cdn.com", $header);
    }

    #[Test]
    public function testIncludesCustomNavigationDirectives(): void
    {
        $customNavigation = new NavigationDirectives(
            frameAncestors: "'none'",
            baseUri: "'none'",
            formAction: "'self' https://submit.example.com"
        );

        $directives = (new CspDirectives())->withNavigation($customNavigation);
        $header     = $directives->toHeaderValue('test-nonce');

        $this->assertStringContainsString("frame-ancestors 'none'", $header);
        $this->assertStringContainsString("base-uri 'none'", $header);
        $this->assertStringContainsString("form-action 'self' https://submit.example.com", $header);
    }
}
