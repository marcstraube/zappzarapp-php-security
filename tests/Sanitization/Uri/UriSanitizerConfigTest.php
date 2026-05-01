<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Uri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizerConfig;

#[CoversClass(UriSanitizerConfig::class)]
final class UriSanitizerConfigTest extends TestCase
{
    // =========================================================================
    // Constructor and Default Values
    // =========================================================================

    #[Test]
    public function testDefaultConstructorValues(): void
    {
        $config = new UriSanitizerConfig();

        $this->assertSame(['http', 'https', 'mailto', 'tel'], $config->allowedSchemes);
        $this->assertSame(['javascript', 'vbscript', 'data'], $config->blockedSchemes);
        $this->assertSame([], $config->allowedHosts);
        $this->assertSame([], $config->blockedHosts);
        $this->assertTrue($config->allowRelative);
        $this->assertFalse($config->allowDataUri);
        $this->assertTrue($config->blockMixedScriptIdn);
        $this->assertFalse($config->blockPrivateNetworks);
    }

    #[Test]
    public function testConstructorWithCustomValues(): void
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: ['javascript'],
            allowedHosts: ['example.com'],
            blockedHosts: ['evil.com'],
            allowRelative: false,
            allowDataUri: true,
            blockMixedScriptIdn: false,
            blockPrivateNetworks: true
        );

        $this->assertSame(['https'], $config->allowedSchemes);
        $this->assertSame(['javascript'], $config->blockedSchemes);
        $this->assertSame(['example.com'], $config->allowedHosts);
        $this->assertSame(['evil.com'], $config->blockedHosts);
        $this->assertFalse($config->allowRelative);
        $this->assertTrue($config->allowDataUri);
        $this->assertFalse($config->blockMixedScriptIdn);
        $this->assertTrue($config->blockPrivateNetworks);
    }

    // =========================================================================
    // Factory Method: strict()
    // =========================================================================

    #[Test]
    public function testStrictConfigValues(): void
    {
        $config = UriSanitizerConfig::strict();

        $this->assertSame(['https'], $config->allowedSchemes);
        $this->assertSame(['javascript', 'vbscript', 'data', 'file'], $config->blockedSchemes);
        $this->assertSame([], $config->allowedHosts);
        $this->assertSame([], $config->blockedHosts);
        $this->assertFalse($config->allowRelative);
        $this->assertFalse($config->allowDataUri);
        $this->assertTrue($config->blockMixedScriptIdn);
    }

    #[Test]
    public function testStrictConfigOnlyAllowsHttps(): void
    {
        $config = UriSanitizerConfig::strict();

        $this->assertContains('https', $config->allowedSchemes);
        $this->assertNotContains('http', $config->allowedSchemes);
        $this->assertNotContains('ftp', $config->allowedSchemes);
    }

    // =========================================================================
    // Factory Method: web()
    // =========================================================================

    #[Test]
    public function testWebConfigValues(): void
    {
        $config = UriSanitizerConfig::web();

        $this->assertSame(['http', 'https', 'mailto', 'tel'], $config->allowedSchemes);
        $this->assertSame(['javascript', 'vbscript', 'data'], $config->blockedSchemes);
        $this->assertSame([], $config->allowedHosts);
        $this->assertSame([], $config->blockedHosts);
        $this->assertTrue($config->allowRelative);
        $this->assertFalse($config->allowDataUri);
        $this->assertTrue($config->blockMixedScriptIdn);
    }

    #[Test]
    public function testWebConfigAllowsCommonSchemes(): void
    {
        $config = UriSanitizerConfig::web();

        $this->assertContains('http', $config->allowedSchemes);
        $this->assertContains('https', $config->allowedSchemes);
        $this->assertContains('mailto', $config->allowedSchemes);
        $this->assertContains('tel', $config->allowedSchemes);
    }

    // =========================================================================
    // withAllowedSchemes() - Immutability
    // =========================================================================

    #[Test]
    public function testWithAllowedSchemesReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig();
        $modified = $original->withAllowedSchemes(['https']);

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithAllowedSchemesDoesNotModifyOriginal(): void
    {
        $original        = new UriSanitizerConfig();
        $originalSchemes = $original->allowedSchemes;

        $original->withAllowedSchemes(['https']);

        $this->assertSame($originalSchemes, $original->allowedSchemes);
    }

    #[Test]
    public function testWithAllowedSchemesPreservesOtherProperties(): void
    {
        $original = new UriSanitizerConfig(
            blockedSchemes: ['evil'],
            allowedHosts: ['good.com'],
            blockedHosts: ['bad.com'],
            allowRelative: false,
            allowDataUri: true,
            blockMixedScriptIdn: false
        );

        $modified = $original->withAllowedSchemes(['ftp']);

        $this->assertSame(['ftp'], $modified->allowedSchemes);
        $this->assertSame(['evil'], $modified->blockedSchemes);
        $this->assertSame(['good.com'], $modified->allowedHosts);
        $this->assertSame(['bad.com'], $modified->blockedHosts);
        $this->assertFalse($modified->allowRelative);
        $this->assertTrue($modified->allowDataUri);
        $this->assertFalse($modified->blockMixedScriptIdn);
    }

    // =========================================================================
    // withBlockedSchemes() - Immutability
    // =========================================================================

    #[Test]
    public function testWithBlockedSchemesReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig();
        $modified = $original->withBlockedSchemes(['custom']);

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithBlockedSchemesDoesNotModifyOriginal(): void
    {
        $original        = new UriSanitizerConfig();
        $originalSchemes = $original->blockedSchemes;

        $original->withBlockedSchemes(['custom']);

        $this->assertSame($originalSchemes, $original->blockedSchemes);
    }

    #[Test]
    public function testWithBlockedSchemesPreservesOtherProperties(): void
    {
        $original = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            allowedHosts: ['good.com'],
            allowRelative: false
        );

        $modified = $original->withBlockedSchemes(['file', 'ftp']);

        $this->assertSame(['https'], $modified->allowedSchemes);
        $this->assertSame(['file', 'ftp'], $modified->blockedSchemes);
        $this->assertSame(['good.com'], $modified->allowedHosts);
        $this->assertFalse($modified->allowRelative);
    }

    // =========================================================================
    // withAllowedHosts() - Immutability
    // =========================================================================

    #[Test]
    public function testWithAllowedHostsReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig();
        $modified = $original->withAllowedHosts(['example.com']);

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithAllowedHostsDoesNotModifyOriginal(): void
    {
        $original      = new UriSanitizerConfig();
        $originalHosts = $original->allowedHosts;

        $original->withAllowedHosts(['example.com']);

        $this->assertSame($originalHosts, $original->allowedHosts);
    }

    #[Test]
    public function testWithAllowedHostsPreservesOtherProperties(): void
    {
        $original = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: ['javascript'],
            blockedHosts: ['bad.com'],
            allowRelative: false,
            blockMixedScriptIdn: false
        );

        $modified = $original->withAllowedHosts(['trusted.com', 'safe.org']);

        $this->assertSame(['https'], $modified->allowedSchemes);
        $this->assertSame(['javascript'], $modified->blockedSchemes);
        $this->assertSame(['trusted.com', 'safe.org'], $modified->allowedHosts);
        $this->assertSame(['bad.com'], $modified->blockedHosts);
        $this->assertFalse($modified->allowRelative);
        $this->assertFalse($modified->blockMixedScriptIdn);
    }

    // =========================================================================
    // withRelative() / withoutRelative() - Immutability
    // =========================================================================

    #[Test]
    public function testWithRelativeReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(allowRelative: false);
        $modified = $original->withRelative();

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithRelativeEnablesRelativeUris(): void
    {
        $original = new UriSanitizerConfig(allowRelative: false);
        $modified = $original->withRelative();

        $this->assertFalse($original->allowRelative);
        $this->assertTrue($modified->allowRelative);
    }

    #[Test]
    public function testWithoutRelativeReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(allowRelative: true);
        $modified = $original->withoutRelative();

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithoutRelativeDisablesRelativeUris(): void
    {
        $original = new UriSanitizerConfig(allowRelative: true);
        $modified = $original->withoutRelative();

        $this->assertTrue($original->allowRelative);
        $this->assertFalse($modified->allowRelative);
    }

    #[Test]
    public function testWithRelativePreservesOtherProperties(): void
    {
        $original = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: ['javascript'],
            allowedHosts: ['example.com'],
            allowRelative: false,
            blockMixedScriptIdn: false
        );

        $modified = $original->withRelative();

        $this->assertSame(['https'], $modified->allowedSchemes);
        $this->assertSame(['javascript'], $modified->blockedSchemes);
        $this->assertSame(['example.com'], $modified->allowedHosts);
        $this->assertTrue($modified->allowRelative);
        $this->assertFalse($modified->blockMixedScriptIdn);
    }

    // =========================================================================
    // withMixedScriptIdnBlocking() / withoutMixedScriptIdnBlocking()
    // =========================================================================

    #[Test]
    public function testWithMixedScriptIdnBlockingReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(blockMixedScriptIdn: false);
        $modified = $original->withMixedScriptIdnBlocking();

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithMixedScriptIdnBlockingEnablesBlocking(): void
    {
        $original = new UriSanitizerConfig(blockMixedScriptIdn: false);
        $modified = $original->withMixedScriptIdnBlocking();

        $this->assertFalse($original->blockMixedScriptIdn);
        $this->assertTrue($modified->blockMixedScriptIdn);
    }

    #[Test]
    public function testWithoutMixedScriptIdnBlockingReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(blockMixedScriptIdn: true);
        $modified = $original->withoutMixedScriptIdnBlocking();

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithoutMixedScriptIdnBlockingDisablesBlocking(): void
    {
        $original = new UriSanitizerConfig(blockMixedScriptIdn: true);
        $modified = $original->withoutMixedScriptIdnBlocking();

        $this->assertTrue($original->blockMixedScriptIdn);
        $this->assertFalse($modified->blockMixedScriptIdn);
    }

    #[Test]
    public function testWithMixedScriptIdnBlockingPreservesOtherProperties(): void
    {
        $original = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            allowedHosts: ['example.com'],
            allowRelative: false,
            allowDataUri: true,
            blockMixedScriptIdn: false
        );

        $modified = $original->withMixedScriptIdnBlocking();

        $this->assertSame(['https'], $modified->allowedSchemes);
        $this->assertSame(['example.com'], $modified->allowedHosts);
        $this->assertFalse($modified->allowRelative);
        $this->assertTrue($modified->allowDataUri);
        $this->assertTrue($modified->blockMixedScriptIdn);
    }

    // =========================================================================
    // Chaining with* Methods
    // =========================================================================

    #[Test]
    public function testWithMethodsCanBeChained(): void
    {
        $config = (new UriSanitizerConfig())
            ->withAllowedSchemes(['https'])
            ->withBlockedSchemes(['javascript', 'data'])
            ->withAllowedHosts(['trusted.com'])
            ->withoutRelative()
            ->withMixedScriptIdnBlocking();

        $this->assertSame(['https'], $config->allowedSchemes);
        $this->assertSame(['javascript', 'data'], $config->blockedSchemes);
        $this->assertSame(['trusted.com'], $config->allowedHosts);
        $this->assertFalse($config->allowRelative);
        $this->assertTrue($config->blockMixedScriptIdn);
    }

    // =========================================================================
    // Security: XSS Prevention via Scheme Blocking
    // =========================================================================

    #[Test]
    public function testDefaultBlocksDangerousSchemes(): void
    {
        $config = new UriSanitizerConfig();

        $this->assertContains('javascript', $config->blockedSchemes);
        $this->assertContains('vbscript', $config->blockedSchemes);
        $this->assertContains('data', $config->blockedSchemes);
    }

    #[Test]
    public function testStrictBlocksFileScheme(): void
    {
        $config = UriSanitizerConfig::strict();

        $this->assertContains('file', $config->blockedSchemes);
    }

    #[Test]
    public function testWebConfigBlocksDangerousSchemes(): void
    {
        $config = UriSanitizerConfig::web();

        $this->assertContains('javascript', $config->blockedSchemes);
        $this->assertContains('vbscript', $config->blockedSchemes);
        $this->assertContains('data', $config->blockedSchemes);
    }

    // =========================================================================
    // Security: Homograph Attack Prevention
    // =========================================================================

    #[Test]
    public function testDefaultEnablesMixedScriptIdnBlocking(): void
    {
        $config = new UriSanitizerConfig();

        $this->assertTrue($config->blockMixedScriptIdn);
    }

    #[Test]
    public function testStrictEnablesMixedScriptIdnBlocking(): void
    {
        $config = UriSanitizerConfig::strict();

        $this->assertTrue($config->blockMixedScriptIdn);
    }

    #[Test]
    public function testWebEnablesMixedScriptIdnBlocking(): void
    {
        $config = UriSanitizerConfig::web();

        $this->assertTrue($config->blockMixedScriptIdn);
    }

    // =========================================================================
    // Factory Methods Create New Instances
    // =========================================================================

    #[Test]
    public function testFactoryMethodsCreateNewInstances(): void
    {
        $strict1 = UriSanitizerConfig::strict();
        $strict2 = UriSanitizerConfig::strict();

        $this->assertNotSame($strict1, $strict2);

        $web1 = UriSanitizerConfig::web();
        $web2 = UriSanitizerConfig::web();

        $this->assertNotSame($web1, $web2);
    }

    // =========================================================================
    // Readonly Properties
    // =========================================================================

    #[Test]
    public function testPropertiesArePublicReadonly(): void
    {
        $config = new UriSanitizerConfig();

        $this->assertIsArray($config->allowedSchemes);
        $this->assertIsArray($config->blockedSchemes);
        $this->assertIsArray($config->allowedHosts);
        $this->assertIsArray($config->blockedHosts);
        $this->assertIsBool($config->allowRelative);
        $this->assertIsBool($config->allowDataUri);
        $this->assertIsBool($config->blockMixedScriptIdn);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    #[Test]
    public function testWithAllowedSchemesEmptyArray(): void
    {
        $config = (new UriSanitizerConfig())->withAllowedSchemes([]);

        $this->assertSame([], $config->allowedSchemes);
    }

    #[Test]
    public function testWithBlockedSchemesEmptyArray(): void
    {
        $config = (new UriSanitizerConfig())->withBlockedSchemes([]);

        $this->assertSame([], $config->blockedSchemes);
    }

    #[Test]
    public function testWithAllowedHostsEmptyArray(): void
    {
        $config = (new UriSanitizerConfig())->withAllowedHosts([]);

        $this->assertSame([], $config->allowedHosts);
    }

    // =========================================================================
    // Factory Method: serverSide()
    // =========================================================================

    #[Test]
    public function testServerSideConfigValues(): void
    {
        $config = UriSanitizerConfig::serverSide();

        $this->assertSame(['http', 'https'], $config->allowedSchemes);
        $this->assertSame(['javascript', 'vbscript', 'data', 'file', 'ftp', 'gopher'], $config->blockedSchemes);
        $this->assertSame([], $config->allowedHosts);
        $this->assertSame([], $config->blockedHosts);
        $this->assertFalse($config->allowRelative);
        $this->assertFalse($config->allowDataUri);
        $this->assertTrue($config->blockMixedScriptIdn);
        $this->assertTrue($config->blockPrivateNetworks);
    }

    #[Test]
    public function testServerSideConfigBlocksFileScheme(): void
    {
        $config = UriSanitizerConfig::serverSide();

        $this->assertContains('file', $config->blockedSchemes);
        $this->assertContains('ftp', $config->blockedSchemes);
        $this->assertContains('gopher', $config->blockedSchemes);
    }

    #[Test]
    public function testServerSideConfigEnablesSsrfProtection(): void
    {
        $config = UriSanitizerConfig::serverSide();

        $this->assertTrue($config->blockPrivateNetworks);
    }

    #[Test]
    public function testServerSideConfigDisallowsRelativeUrls(): void
    {
        $config = UriSanitizerConfig::serverSide();

        $this->assertFalse($config->allowRelative);
    }

    // =========================================================================
    // withPrivateNetworkBlocking() / withoutPrivateNetworkBlocking()
    // =========================================================================

    #[Test]
    public function testWithPrivateNetworkBlockingReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(blockPrivateNetworks: false);
        $modified = $original->withPrivateNetworkBlocking();

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithPrivateNetworkBlockingEnablesBlocking(): void
    {
        $original = new UriSanitizerConfig(blockPrivateNetworks: false);
        $modified = $original->withPrivateNetworkBlocking();

        $this->assertFalse($original->blockPrivateNetworks);
        $this->assertTrue($modified->blockPrivateNetworks);
    }

    #[Test]
    public function testWithoutPrivateNetworkBlockingReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(blockPrivateNetworks: true);
        $modified = $original->withoutPrivateNetworkBlocking();

        $this->assertNotSame($original, $modified);
    }

    #[Test]
    public function testWithoutPrivateNetworkBlockingDisablesBlocking(): void
    {
        $original = new UriSanitizerConfig(blockPrivateNetworks: true);
        $modified = $original->withoutPrivateNetworkBlocking();

        $this->assertTrue($original->blockPrivateNetworks);
        $this->assertFalse($modified->blockPrivateNetworks);
    }

    #[Test]
    public function testWithPrivateNetworkBlockingPreservesOtherProperties(): void
    {
        $original = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            allowedHosts: ['example.com'],
            allowRelative: false,
            allowDataUri: true,
            blockMixedScriptIdn: false,
            blockPrivateNetworks: false
        );

        $modified = $original->withPrivateNetworkBlocking();

        $this->assertSame(['https'], $modified->allowedSchemes);
        $this->assertSame(['example.com'], $modified->allowedHosts);
        $this->assertFalse($modified->allowRelative);
        $this->assertTrue($modified->allowDataUri);
        $this->assertFalse($modified->blockMixedScriptIdn);
        $this->assertTrue($modified->blockPrivateNetworks);
    }

    // =========================================================================
    // Chaining with* Methods (including new private network methods)
    // =========================================================================

    #[Test]
    public function testWithMethodsCanBeChainedWithPrivateNetworkBlocking(): void
    {
        $config = (new UriSanitizerConfig())
            ->withAllowedSchemes(['https'])
            ->withBlockedSchemes(['javascript', 'data'])
            ->withAllowedHosts(['trusted.com'])
            ->withoutRelative()
            ->withMixedScriptIdnBlocking()
            ->withPrivateNetworkBlocking();

        $this->assertSame(['https'], $config->allowedSchemes);
        $this->assertSame(['javascript', 'data'], $config->blockedSchemes);
        $this->assertSame(['trusted.com'], $config->allowedHosts);
        $this->assertFalse($config->allowRelative);
        $this->assertTrue($config->blockMixedScriptIdn);
        $this->assertTrue($config->blockPrivateNetworks);
    }

    // =========================================================================
    // Security: SSRF Prevention
    // =========================================================================

    #[Test]
    public function testDefaultDoesNotEnableSsrfProtection(): void
    {
        $config = new UriSanitizerConfig();

        $this->assertFalse($config->blockPrivateNetworks);
    }

    #[Test]
    public function testWebConfigDoesNotEnableSsrfProtection(): void
    {
        $config = UriSanitizerConfig::web();

        $this->assertFalse($config->blockPrivateNetworks);
    }

    #[Test]
    public function testStrictConfigDoesNotEnableSsrfProtection(): void
    {
        $config = UriSanitizerConfig::strict();

        $this->assertFalse($config->blockPrivateNetworks);
    }

    // =========================================================================
    // Readonly Properties (including new property)
    // =========================================================================

    #[Test]
    public function testBlockPrivateNetworksPropertyIsPublicReadonly(): void
    {
        $config = new UriSanitizerConfig();

        $this->assertIsBool($config->blockPrivateNetworks);
    }

    // =========================================================================
    // Factory Methods Create New Instances (including serverSide)
    // =========================================================================

    #[Test]
    public function testServerSideFactoryCreatesNewInstances(): void
    {
        $serverSide1 = UriSanitizerConfig::serverSide();
        $serverSide2 = UriSanitizerConfig::serverSide();

        $this->assertNotSame($serverSide1, $serverSide2);
    }
}
