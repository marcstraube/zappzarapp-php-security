<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Uri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizerConfig;

#[CoversClass(UriSanitizerConfig::class)]
final class UriSanitizerConfigTest extends TestCase
{
    // =========================================================================
    // Constructor and Default Values
    // =========================================================================

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

    public function testWithAllowedSchemesReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig();
        $modified = $original->withAllowedSchemes(['https']);

        $this->assertNotSame($original, $modified);
    }

    public function testWithAllowedSchemesDoesNotModifyOriginal(): void
    {
        $original        = new UriSanitizerConfig();
        $originalSchemes = $original->allowedSchemes;

        $original->withAllowedSchemes(['https']);

        $this->assertSame($originalSchemes, $original->allowedSchemes);
    }

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

    public function testWithBlockedSchemesReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig();
        $modified = $original->withBlockedSchemes(['custom']);

        $this->assertNotSame($original, $modified);
    }

    public function testWithBlockedSchemesDoesNotModifyOriginal(): void
    {
        $original        = new UriSanitizerConfig();
        $originalSchemes = $original->blockedSchemes;

        $original->withBlockedSchemes(['custom']);

        $this->assertSame($originalSchemes, $original->blockedSchemes);
    }

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

    public function testWithAllowedHostsReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig();
        $modified = $original->withAllowedHosts(['example.com']);

        $this->assertNotSame($original, $modified);
    }

    public function testWithAllowedHostsDoesNotModifyOriginal(): void
    {
        $original      = new UriSanitizerConfig();
        $originalHosts = $original->allowedHosts;

        $original->withAllowedHosts(['example.com']);

        $this->assertSame($originalHosts, $original->allowedHosts);
    }

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

    public function testWithRelativeReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(allowRelative: false);
        $modified = $original->withRelative();

        $this->assertNotSame($original, $modified);
    }

    public function testWithRelativeEnablesRelativeUris(): void
    {
        $original = new UriSanitizerConfig(allowRelative: false);
        $modified = $original->withRelative();

        $this->assertFalse($original->allowRelative);
        $this->assertTrue($modified->allowRelative);
    }

    public function testWithoutRelativeReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(allowRelative: true);
        $modified = $original->withoutRelative();

        $this->assertNotSame($original, $modified);
    }

    public function testWithoutRelativeDisablesRelativeUris(): void
    {
        $original = new UriSanitizerConfig(allowRelative: true);
        $modified = $original->withoutRelative();

        $this->assertTrue($original->allowRelative);
        $this->assertFalse($modified->allowRelative);
    }

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

    public function testWithMixedScriptIdnBlockingReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(blockMixedScriptIdn: false);
        $modified = $original->withMixedScriptIdnBlocking();

        $this->assertNotSame($original, $modified);
    }

    public function testWithMixedScriptIdnBlockingEnablesBlocking(): void
    {
        $original = new UriSanitizerConfig(blockMixedScriptIdn: false);
        $modified = $original->withMixedScriptIdnBlocking();

        $this->assertFalse($original->blockMixedScriptIdn);
        $this->assertTrue($modified->blockMixedScriptIdn);
    }

    public function testWithoutMixedScriptIdnBlockingReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(blockMixedScriptIdn: true);
        $modified = $original->withoutMixedScriptIdnBlocking();

        $this->assertNotSame($original, $modified);
    }

    public function testWithoutMixedScriptIdnBlockingDisablesBlocking(): void
    {
        $original = new UriSanitizerConfig(blockMixedScriptIdn: true);
        $modified = $original->withoutMixedScriptIdnBlocking();

        $this->assertTrue($original->blockMixedScriptIdn);
        $this->assertFalse($modified->blockMixedScriptIdn);
    }

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

    public function testDefaultBlocksDangerousSchemes(): void
    {
        $config = new UriSanitizerConfig();

        $this->assertContains('javascript', $config->blockedSchemes);
        $this->assertContains('vbscript', $config->blockedSchemes);
        $this->assertContains('data', $config->blockedSchemes);
    }

    public function testStrictBlocksFileScheme(): void
    {
        $config = UriSanitizerConfig::strict();

        $this->assertContains('file', $config->blockedSchemes);
    }

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

    public function testDefaultEnablesMixedScriptIdnBlocking(): void
    {
        $config = new UriSanitizerConfig();

        $this->assertTrue($config->blockMixedScriptIdn);
    }

    public function testStrictEnablesMixedScriptIdnBlocking(): void
    {
        $config = UriSanitizerConfig::strict();

        $this->assertTrue($config->blockMixedScriptIdn);
    }

    public function testWebEnablesMixedScriptIdnBlocking(): void
    {
        $config = UriSanitizerConfig::web();

        $this->assertTrue($config->blockMixedScriptIdn);
    }

    // =========================================================================
    // Factory Methods Create New Instances
    // =========================================================================

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

    public function testWithAllowedSchemesEmptyArray(): void
    {
        $config = (new UriSanitizerConfig())->withAllowedSchemes([]);

        $this->assertSame([], $config->allowedSchemes);
    }

    public function testWithBlockedSchemesEmptyArray(): void
    {
        $config = (new UriSanitizerConfig())->withBlockedSchemes([]);

        $this->assertSame([], $config->blockedSchemes);
    }

    public function testWithAllowedHostsEmptyArray(): void
    {
        $config = (new UriSanitizerConfig())->withAllowedHosts([]);

        $this->assertSame([], $config->allowedHosts);
    }

    // =========================================================================
    // Factory Method: serverSide()
    // =========================================================================

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

    public function testServerSideConfigBlocksFileScheme(): void
    {
        $config = UriSanitizerConfig::serverSide();

        $this->assertContains('file', $config->blockedSchemes);
        $this->assertContains('ftp', $config->blockedSchemes);
        $this->assertContains('gopher', $config->blockedSchemes);
    }

    public function testServerSideConfigEnablesSsrfProtection(): void
    {
        $config = UriSanitizerConfig::serverSide();

        $this->assertTrue($config->blockPrivateNetworks);
    }

    public function testServerSideConfigDisallowsRelativeUrls(): void
    {
        $config = UriSanitizerConfig::serverSide();

        $this->assertFalse($config->allowRelative);
    }

    // =========================================================================
    // withPrivateNetworkBlocking() / withoutPrivateNetworkBlocking()
    // =========================================================================

    public function testWithPrivateNetworkBlockingReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(blockPrivateNetworks: false);
        $modified = $original->withPrivateNetworkBlocking();

        $this->assertNotSame($original, $modified);
    }

    public function testWithPrivateNetworkBlockingEnablesBlocking(): void
    {
        $original = new UriSanitizerConfig(blockPrivateNetworks: false);
        $modified = $original->withPrivateNetworkBlocking();

        $this->assertFalse($original->blockPrivateNetworks);
        $this->assertTrue($modified->blockPrivateNetworks);
    }

    public function testWithoutPrivateNetworkBlockingReturnsNewInstance(): void
    {
        $original = new UriSanitizerConfig(blockPrivateNetworks: true);
        $modified = $original->withoutPrivateNetworkBlocking();

        $this->assertNotSame($original, $modified);
    }

    public function testWithoutPrivateNetworkBlockingDisablesBlocking(): void
    {
        $original = new UriSanitizerConfig(blockPrivateNetworks: true);
        $modified = $original->withoutPrivateNetworkBlocking();

        $this->assertTrue($original->blockPrivateNetworks);
        $this->assertFalse($modified->blockPrivateNetworks);
    }

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

    public function testDefaultDoesNotEnableSsrfProtection(): void
    {
        $config = new UriSanitizerConfig();

        $this->assertFalse($config->blockPrivateNetworks);
    }

    public function testWebConfigDoesNotEnableSsrfProtection(): void
    {
        $config = UriSanitizerConfig::web();

        $this->assertFalse($config->blockPrivateNetworks);
    }

    public function testStrictConfigDoesNotEnableSsrfProtection(): void
    {
        $config = UriSanitizerConfig::strict();

        $this->assertFalse($config->blockPrivateNetworks);
    }

    // =========================================================================
    // Readonly Properties (including new property)
    // =========================================================================

    public function testBlockPrivateNetworksPropertyIsPublicReadonly(): void
    {
        $config = new UriSanitizerConfig();

        $this->assertIsBool($config->blockPrivateNetworks);
    }

    // =========================================================================
    // Factory Methods Create New Instances (including serverSide)
    // =========================================================================

    public function testServerSideFactoryCreatesNewInstances(): void
    {
        $serverSide1 = UriSanitizerConfig::serverSide();
        $serverSide2 = UriSanitizerConfig::serverSide();

        $this->assertNotSame($serverSide1, $serverSide2);
    }
}
