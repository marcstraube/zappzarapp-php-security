<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\NavigationDirectives;
use Zappzarapp\Security\Csp\Directive\ReportingConfig;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;
use Zappzarapp\Security\Csp\SecurityPolicy;

/**
 * Tests for CspDirectives constructor defaults and configuration
 */
final class CspDirectivesConstructorTest extends TestCase
{
    // Default Values
    #[Test]
    public function testDefaultsToStrictPolicy(): void
    {
        $directives = new CspDirectives();

        $this->assertSame(SecurityPolicy::STRICT, $directives->securityPolicy);
    }

    #[Test]
    public function testDefaultsToNullWebSocketHost(): void
    {
        $directives = new CspDirectives();

        $this->assertNull($directives->websocketHost);
    }

    #[Test]
    public function testDefaultsToSelfDefaultSrc(): void
    {
        $directives = new CspDirectives();

        $this->assertSame("'self'", $directives->defaultSrc);
    }

    #[Test]
    public function testDefaultsToNullScriptSrc(): void
    {
        $directives = new CspDirectives();

        $this->assertNull($directives->scriptSrc);
    }

    #[Test]
    public function testDefaultsToNullStyleSrc(): void
    {
        $directives = new CspDirectives();

        $this->assertNull($directives->styleSrc);
    }

    #[Test]
    public function testDefaultsToNewResourceDirectives(): void
    {
        $directives = new CspDirectives();

        $this->assertInstanceOf(ResourceDirectives::class, $directives->resources);
        $this->assertSame("'self' data:", $directives->resources->img);
    }

    #[Test]
    public function testDefaultsToNewNavigationDirectives(): void
    {
        $directives = new CspDirectives();

        $this->assertInstanceOf(NavigationDirectives::class, $directives->navigation);
        $this->assertSame("'self'", $directives->navigation->frameAncestors);
    }

    #[Test]
    public function testDefaultsToNewReportingConfig(): void
    {
        $directives = new CspDirectives();

        $this->assertInstanceOf(ReportingConfig::class, $directives->reporting);
        $this->assertTrue($directives->reporting->upgradeInsecure);
    }

    // Custom Values via Constructor
    #[Test]
    public function testWithLenientPolicy(): void
    {
        $directives = new CspDirectives(securityPolicy: SecurityPolicy::LENIENT);

        $this->assertSame(SecurityPolicy::LENIENT, $directives->securityPolicy);
    }

    #[Test]
    public function testWithWebSocketHost(): void
    {
        $directives = new CspDirectives(websocketHost: '192.168.1.100:5173');

        $this->assertSame('192.168.1.100:5173', $directives->websocketHost);
    }

    #[Test]
    public function testWithCustomDefaultSrc(): void
    {
        $directives = new CspDirectives(defaultSrc: "'self' https://example.com");

        $this->assertSame("'self' https://example.com", $directives->defaultSrc);
    }

    #[Test]
    public function testWithCustomScriptSrc(): void
    {
        $directives = new CspDirectives(scriptSrc: "'self' https://cdn.example.com");

        $this->assertSame("'self' https://cdn.example.com", $directives->scriptSrc);
    }

    #[Test]
    public function testWithCustomStyleSrc(): void
    {
        $directives = new CspDirectives(styleSrc: "'self' https://fonts.googleapis.com");

        $this->assertSame("'self' https://fonts.googleapis.com", $directives->styleSrc);
    }

    #[Test]
    public function testWithCustomResources(): void
    {
        $resources  = new ResourceDirectives(img: "'none'");
        $directives = new CspDirectives(resources: $resources);

        $this->assertSame("'none'", $directives->resources->img);
    }

    #[Test]
    public function testWithCustomNavigation(): void
    {
        $navigation = new NavigationDirectives(frameAncestors: "'none'");
        $directives = new CspDirectives(navigation: $navigation);

        $this->assertSame("'none'", $directives->navigation->frameAncestors);
    }

    #[Test]
    public function testWithCustomReporting(): void
    {
        $reporting  = new ReportingConfig(upgradeInsecure: false, uri: '/report');
        $directives = new CspDirectives(reporting: $reporting);

        $this->assertFalse($directives->reporting->upgradeInsecure);
        $this->assertSame('/report', $directives->reporting->uri);
    }

    // Combined Configuration
    #[Test]
    public function testFullCustomConfiguration(): void
    {
        $directives = new CspDirectives(
            defaultSrc: "'self' https://example.com",
            scriptSrc: "'self' https://scripts.example.com",
            styleSrc: "'self' https://styles.example.com",
            resources: new ResourceDirectives(img: "'self' https://images.example.com"),
            navigation: new NavigationDirectives(frameAncestors: "'none'"),
            websocketHost: 'ws.example.com:443',
            securityPolicy: SecurityPolicy::UNSAFE_EVAL,
            reporting: new ReportingConfig(uri: '/csp-report'),
        );

        $this->assertSame("'self' https://example.com", $directives->defaultSrc);
        $this->assertSame("'self' https://scripts.example.com", $directives->scriptSrc);
        $this->assertSame("'self' https://styles.example.com", $directives->styleSrc);
        $this->assertSame("'self' https://images.example.com", $directives->resources->img);
        $this->assertSame("'none'", $directives->navigation->frameAncestors);
        $this->assertSame('ws.example.com:443', $directives->websocketHost);
        $this->assertSame(SecurityPolicy::UNSAFE_EVAL, $directives->securityPolicy);
        $this->assertSame('/csp-report', $directives->reporting->uri);
    }
}
