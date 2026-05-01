<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

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
 * Tests for CspDirectives fluent API (with* methods) and immutability
 */
final class CspDirectivesFluentApiTest extends TestCase
{
    // Immutability
    #[Test]
    public function testWithMethodsReturnNewInstance(): void
    {
        $original = new CspDirectives();
        $modified = $original->withImgSrc("'self' https://cdn.example.com");

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testOriginalRemainsUnchanged(): void
    {
        $original = new CspDirectives();
        $original->withImgSrc("'self' https://cdn.example.com");

        $this->assertSame("'self' data:", $original->resources->img);
    }

    // Single with* Methods
    #[Test]
    public function testWithDefaultSrc(): void
    {
        $modified = (new CspDirectives())->withDefaultSrc("'none'");

        $this->assertSame("'none'", $modified->defaultSrc);
    }

    #[Test]
    public function testWithScriptSrc(): void
    {
        $modified = (new CspDirectives())->withScriptSrc("'self' https://scripts.com");

        $this->assertSame("'self' https://scripts.com", $modified->scriptSrc);
    }

    #[Test]
    public function testWithStyleSrc(): void
    {
        $modified = (new CspDirectives())->withStyleSrc("'self' https://styles.com");

        $this->assertSame("'self' https://styles.com", $modified->styleSrc);
    }

    #[Test]
    public function testWithImgSrc(): void
    {
        $modified = (new CspDirectives())->withImgSrc("'self' https://images.com");

        $this->assertSame("'self' https://images.com", $modified->resources->img);
    }

    #[Test]
    public function testWithFontSrc(): void
    {
        $modified = (new CspDirectives())->withFontSrc("'self' https://fonts.com");

        $this->assertSame("'self' https://fonts.com", $modified->resources->font);
    }

    #[Test]
    public function testWithConnectSrc(): void
    {
        $modified = (new CspDirectives())->withConnectSrc("'self' https://api.com");

        $this->assertSame("'self' https://api.com", $modified->resources->connect);
    }

    #[Test]
    public function testWithWebSocket(): void
    {
        $modified = (new CspDirectives())->withWebSocket('ws.example.com:443');

        $this->assertSame('ws.example.com:443', $modified->websocketHost);
    }

    #[Test]
    public function testWithFrameAncestors(): void
    {
        $modified = (new CspDirectives())->withFrameAncestors("'none'");

        $this->assertSame("'none'", $modified->navigation->frameAncestors);
    }

    #[Test]
    public function testWithBaseUri(): void
    {
        $modified = (new CspDirectives())->withBaseUri("'none'");

        $this->assertSame("'none'", $modified->navigation->baseUri);
    }

    #[Test]
    public function testWithFormAction(): void
    {
        $modified = (new CspDirectives())->withFormAction("'self' https://submit.com");

        $this->assertSame("'self' https://submit.com", $modified->navigation->formAction);
    }

    #[Test]
    public function testWithSecurityPolicy(): void
    {
        $modified = (new CspDirectives())->withSecurityPolicy(SecurityPolicy::LENIENT);

        $this->assertSame(SecurityPolicy::LENIENT, $modified->securityPolicy);
    }

    #[Test]
    public function testWithResources(): void
    {
        $resources = new ResourceDirectives(img: "'none'", font: "'none'");
        $modified  = (new CspDirectives())->withResources($resources);

        $this->assertSame($resources, $modified->resources);
    }

    #[Test]
    public function testWithNavigation(): void
    {
        $navigation = new NavigationDirectives(frameAncestors: "'none'");
        $modified   = (new CspDirectives())->withNavigation($navigation);

        $this->assertSame($navigation, $modified->navigation);
    }

    #[Test]
    public function testWithReporting(): void
    {
        $reporting = new ReportingConfig(uri: '/report');
        $modified  = (new CspDirectives())->withReporting($reporting);

        $this->assertSame($reporting, $modified->reporting);
    }

    // Convenience Methods (delegating to ReportingConfig)
    #[Test]
    public function testWithUpgradeInsecure(): void
    {
        $modified = (new CspDirectives())->withUpgradeInsecure(false);

        $this->assertFalse($modified->reporting->upgradeInsecure);
    }

    #[Test]
    public function testWithReportUri(): void
    {
        $modified = (new CspDirectives())->withReportUri('/csp-report');

        $this->assertSame('/csp-report', $modified->reporting->uri);
    }

    #[Test]
    public function testWithReportTo(): void
    {
        $modified = (new CspDirectives())->withReportTo('csp-endpoint');

        $this->assertSame('csp-endpoint', $modified->reporting->endpoint);
    }

    // Fluent Chaining
    #[Test]
    public function testFluentInterfaceChaining(): void
    {
        $directives = (new CspDirectives())
            ->withImgSrc("'self' https://images.example.com")
            ->withFontSrc("'self' https://fonts.gstatic.com")
            ->withWebSocket('api.example.com:443');

        $this->assertSame("'self' https://images.example.com", $directives->resources->img);
        $this->assertSame("'self' https://fonts.gstatic.com", $directives->resources->font);
        $this->assertSame('api.example.com:443', $directives->websocketHost);
    }

    #[Test]
    public function testComplexFluentChaining(): void
    {
        $directives = (new CspDirectives())
            ->withDefaultSrc("'self' https://example.com")
            ->withScriptSrc("'self' https://scripts.example.com")
            ->withStyleSrc("'self' https://styles.example.com")
            ->withImgSrc("'self' data: https://images.example.com")
            ->withFontSrc("'self' https://fonts.gstatic.com")
            ->withConnectSrc("'self' https://api.example.com")
            ->withWebSocket('ws.example.com:443')
            ->withFrameAncestors("'none'")
            ->withBaseUri("'self'")
            ->withFormAction("'self'")
            ->withSecurityPolicy(SecurityPolicy::UNSAFE_EVAL)
            ->withUpgradeInsecure(false)
            ->withReportUri('/csp-report')
            ->withReportTo('csp-endpoint');

        $this->assertSame("'self' https://example.com", $directives->defaultSrc);
        $this->assertSame("'self' https://scripts.example.com", $directives->scriptSrc);
        $this->assertSame("'self' https://styles.example.com", $directives->styleSrc);
        $this->assertSame("'self' data: https://images.example.com", $directives->resources->img);
        $this->assertSame("'self' https://fonts.gstatic.com", $directives->resources->font);
        $this->assertSame("'self' https://api.example.com", $directives->resources->connect);
        $this->assertSame('ws.example.com:443', $directives->websocketHost);
        $this->assertSame("'none'", $directives->navigation->frameAncestors);
        $this->assertSame("'self'", $directives->navigation->baseUri);
        $this->assertSame("'self'", $directives->navigation->formAction);
        $this->assertSame(SecurityPolicy::UNSAFE_EVAL, $directives->securityPolicy);
        $this->assertFalse($directives->reporting->upgradeInsecure);
        $this->assertSame('/csp-report', $directives->reporting->uri);
        $this->assertSame('csp-endpoint', $directives->reporting->endpoint);
    }

}
