<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Uri;

/**
 * Configuration for URI sanitizer
 */
final readonly class UriSanitizerConfig
{
    /**
     * @param list<string> $allowedSchemes Allowed URI schemes (lowercase)
     * @param list<string> $blockedSchemes Blocked URI schemes (lowercase)
     * @param list<string> $allowedHosts Allowed hostnames (empty = all allowed)
     * @param list<string> $blockedHosts Blocked hostnames
     * @param bool $allowRelative Allow relative URIs
     * @param bool $allowDataUri Allow data: URIs
     * @param bool $blockMixedScriptIdn Block IDN domains with mixed scripts (homograph attack protection)
     * @param bool $blockPrivateNetworks Block requests to private/internal networks (SSRF protection)
     */
    public function __construct(
        public array $allowedSchemes = ['http', 'https', 'mailto', 'tel'],
        public array $blockedSchemes = ['javascript', 'vbscript', 'data'],
        public array $allowedHosts = [],
        public array $blockedHosts = [],
        public bool $allowRelative = true,
        public bool $allowDataUri = false,
        public bool $blockMixedScriptIdn = true,
        public bool $blockPrivateNetworks = false,
    ) {
    }

    /**
     * Create with allowed schemes
     *
     * @param list<string> $schemes
     */
    public function withAllowedSchemes(array $schemes): self
    {
        return new self(
            $schemes,
            $this->blockedSchemes,
            $this->allowedHosts,
            $this->blockedHosts,
            $this->allowRelative,
            $this->allowDataUri,
            $this->blockMixedScriptIdn,
            $this->blockPrivateNetworks
        );
    }

    /**
     * Create with blocked schemes
     *
     * @param list<string> $schemes
     */
    public function withBlockedSchemes(array $schemes): self
    {
        return new self(
            $this->allowedSchemes,
            $schemes,
            $this->allowedHosts,
            $this->blockedHosts,
            $this->allowRelative,
            $this->allowDataUri,
            $this->blockMixedScriptIdn,
            $this->blockPrivateNetworks
        );
    }

    /**
     * Create with allowed hosts
     *
     * @param list<string> $hosts
     */
    public function withAllowedHosts(array $hosts): self
    {
        return new self(
            $this->allowedSchemes,
            $this->blockedSchemes,
            $hosts,
            $this->blockedHosts,
            $this->allowRelative,
            $this->allowDataUri,
            $this->blockMixedScriptIdn,
            $this->blockPrivateNetworks
        );
    }

    /**
     * Create with relative URIs allowed
     */
    public function withRelative(): self
    {
        return new self(
            $this->allowedSchemes,
            $this->blockedSchemes,
            $this->allowedHosts,
            $this->blockedHosts,
            true,
            $this->allowDataUri,
            $this->blockMixedScriptIdn,
            $this->blockPrivateNetworks
        );
    }

    /**
     * Create with relative URIs blocked
     */
    public function withoutRelative(): self
    {
        return new self(
            $this->allowedSchemes,
            $this->blockedSchemes,
            $this->allowedHosts,
            $this->blockedHosts,
            false,
            $this->allowDataUri,
            $this->blockMixedScriptIdn,
            $this->blockPrivateNetworks
        );
    }

    /**
     * Create with mixed-script IDN blocking enabled
     */
    public function withMixedScriptIdnBlocking(): self
    {
        return new self(
            $this->allowedSchemes,
            $this->blockedSchemes,
            $this->allowedHosts,
            $this->blockedHosts,
            $this->allowRelative,
            $this->allowDataUri,
            true,
            $this->blockPrivateNetworks
        );
    }

    /**
     * Create with mixed-script IDN blocking disabled
     */
    public function withoutMixedScriptIdnBlocking(): self
    {
        return new self(
            $this->allowedSchemes,
            $this->blockedSchemes,
            $this->allowedHosts,
            $this->blockedHosts,
            $this->allowRelative,
            $this->allowDataUri,
            false,
            $this->blockPrivateNetworks
        );
    }

    /**
     * Create with private network blocking enabled (SSRF protection)
     */
    public function withPrivateNetworkBlocking(): self
    {
        return new self(
            $this->allowedSchemes,
            $this->blockedSchemes,
            $this->allowedHosts,
            $this->blockedHosts,
            $this->allowRelative,
            $this->allowDataUri,
            $this->blockMixedScriptIdn,
            true
        );
    }

    /**
     * Create with private network blocking disabled
     */
    public function withoutPrivateNetworkBlocking(): self
    {
        return new self(
            $this->allowedSchemes,
            $this->blockedSchemes,
            $this->allowedHosts,
            $this->blockedHosts,
            $this->allowRelative,
            $this->allowDataUri,
            $this->blockMixedScriptIdn,
            false
        );
    }

    /**
     * Create strict configuration (HTTPS only, mixed-script IDN blocked)
     */
    public static function strict(): self
    {
        return new self(
            allowedSchemes: ['https'],
            blockedSchemes: ['javascript', 'vbscript', 'data', 'file'],
            allowRelative: false,
            blockMixedScriptIdn: true
        );
    }

    /**
     * Create web configuration (common web schemes)
     */
    public static function web(): self
    {
        return new self(
            allowedSchemes: ['http', 'https', 'mailto', 'tel'],
            blockedSchemes: ['javascript', 'vbscript', 'data'],
            allowRelative: true,
            blockMixedScriptIdn: true
        );
    }

    /**
     * Create configuration for server-side requests with SSRF protection
     *
     * Blocks requests to:
     * - Private networks (RFC 1918)
     * - Loopback addresses
     * - Link-local addresses (including cloud metadata)
     * - Internal hostnames
     */
    public static function serverSide(): self
    {
        return new self(
            allowedSchemes: ['http', 'https'],
            blockedSchemes: ['javascript', 'vbscript', 'data', 'file', 'ftp', 'gopher'],
            allowRelative: false,
            blockMixedScriptIdn: true,
            blockPrivateNetworks: true
        );
    }
}
