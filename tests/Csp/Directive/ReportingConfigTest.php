<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\ReportingConfig;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;

final class ReportingConfigTest extends TestCase
{
    // Default Values
    #[Test]
    public function testDefaultValues(): void
    {
        $reporting = new ReportingConfig();

        $this->assertTrue($reporting->upgradeInsecure);
        $this->assertNull($reporting->uri);
        $this->assertNull($reporting->endpoint);
    }

    #[Test]
    public function testCustomValues(): void
    {
        $reporting = new ReportingConfig(
            upgradeInsecure: false,
            uri: '/csp-report',
            endpoint: 'csp-endpoint'
        );

        $this->assertFalse($reporting->upgradeInsecure);
        $this->assertSame('/csp-report', $reporting->uri);
        $this->assertSame('csp-endpoint', $reporting->endpoint);
    }

    // Immutability
    #[Test]
    public function testWithUpgradeInsecureReturnsNewInstance(): void
    {
        $original = new ReportingConfig();
        $modified = $original->withUpgradeInsecure(false);

        $this->assertNotSame($original, $modified);
        $this->assertTrue($original->upgradeInsecure);
        $this->assertFalse($modified->upgradeInsecure);
    }

    #[Test]
    public function testWithUriReturnsNewInstance(): void
    {
        $original = new ReportingConfig();
        $modified = $original->withUri('/csp-report');

        $this->assertNotSame($original, $modified);
        $this->assertNull($original->uri);
        $this->assertSame('/csp-report', $modified->uri);
    }

    #[Test]
    public function testWithEndpointReturnsNewInstance(): void
    {
        $original = new ReportingConfig();
        $modified = $original->withEndpoint('csp-endpoint');

        $this->assertNotSame($original, $modified);
        $this->assertNull($original->endpoint);
        $this->assertSame('csp-endpoint', $modified->endpoint);
    }

    #[Test]
    public function testFluentApiChaining(): void
    {
        $reporting = (new ReportingConfig())
            ->withUpgradeInsecure(false)
            ->withUri('/csp-report')
            ->withEndpoint('csp-endpoint');

        $this->assertFalse($reporting->upgradeInsecure);
        $this->assertSame('/csp-report', $reporting->uri);
        $this->assertSame('csp-endpoint', $reporting->endpoint);
    }

    // Validation
    #[Test]
    public function testValidationThrowsForSemicolonInUri(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('report-uri');

        new ReportingConfig(uri: '/csp-report; evil');
    }

    #[Test]
    public function testValidationThrowsForNewlineInUri(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('report-uri');

        new ReportingConfig(uri: "/csp-report\nevil");
    }

    #[Test]
    public function testValidationThrowsForSemicolonInEndpoint(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('report-to');

        new ReportingConfig(endpoint: 'endpoint; evil');
    }

    #[Test]
    public function testValidationThrowsForNewlineInEndpoint(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('report-to');

        new ReportingConfig(endpoint: "endpoint\nevil");
    }

    #[Test]
    public function testValidationThrowsForCarriageReturnInUri(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('report-uri');

        new ReportingConfig(uri: "/csp-report\revil");
    }

    // --- HTTPS Security Validation ---

    #[Test]
    public function testValidationThrowsForHttpReportUri(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('must use HTTPS');

        new ReportingConfig(uri: 'http://example.com/csp-report');
    }

    #[Test]
    public function testValidationThrowsForUppercaseHttpReportUri(): void
    {
        // Tests that scheme comparison is case-insensitive (kills strtolower mutation)
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('must use HTTPS');

        new ReportingConfig(uri: 'HTTP://example.com/csp-report');
    }

    #[Test]
    public function testValidationThrowsForMixedCaseHttpReportUri(): void
    {
        // Tests mixed case "Http://"
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('must use HTTPS');

        new ReportingConfig(uri: 'Http://example.com/csp-report');
    }

    #[Test]
    public function testValidationAllowsHttpsReportUri(): void
    {
        $config = new ReportingConfig(uri: 'https://example.com/csp-report');

        $this->assertSame('https://example.com/csp-report', $config->uri);
    }

    #[Test]
    public function testValidationAllowsRelativeReportUri(): void
    {
        $config = new ReportingConfig(uri: '/csp-report');

        $this->assertSame('/csp-report', $config->uri);
    }

    #[Test]
    public function testWithUriThrowsForHttpScheme(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('must use HTTPS');

        (new ReportingConfig())->withUri('http://example.com/report');
    }

    // Preservation Tests (kills ?? swap mutations)
    #[Test]
    public function testWithUpgradeInsecurePreservesOtherValues(): void
    {
        $original = new ReportingConfig(
            upgradeInsecure: true,
            uri: '/original-uri',
            endpoint: 'original-endpoint'
        );

        $modified = $original->withUpgradeInsecure(false);

        $this->assertFalse($modified->upgradeInsecure);
        $this->assertSame('/original-uri', $modified->uri);
        $this->assertSame('original-endpoint', $modified->endpoint);
    }

    #[Test]
    public function testWithUriPreservesOtherValues(): void
    {
        $original = new ReportingConfig(
            upgradeInsecure: false,
            uri: '/original-uri',
            endpoint: 'original-endpoint'
        );

        $modified = $original->withUri('/new-uri');

        $this->assertFalse($modified->upgradeInsecure);
        $this->assertSame('/new-uri', $modified->uri);
        $this->assertSame('original-endpoint', $modified->endpoint);
    }

    #[Test]
    public function testWithEndpointPreservesOtherValues(): void
    {
        $original = new ReportingConfig(
            upgradeInsecure: false,
            uri: '/original-uri',
            endpoint: 'original-endpoint'
        );

        $modified = $original->withEndpoint('new-endpoint');

        $this->assertFalse($modified->upgradeInsecure);
        $this->assertSame('/original-uri', $modified->uri);
        $this->assertSame('new-endpoint', $modified->endpoint);
    }
}
