<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Directive;

use InvalidArgumentException;
use Zappzarapp\Security\Csp\Builder\HeaderValueBuilder;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;
use Zappzarapp\Security\Csp\Nonce\NonceProvider;
use Zappzarapp\Security\Csp\SecurityPolicy;
use Zappzarapp\Security\Csp\Validation\ValidatesDirectiveValues;

/**
 * CSP Directives Value Object
 *
 * Immutable configuration for Content Security Policy directives.
 * Provides type-safe CSP configuration with validation.
 *
 * Security by default: Constructor defaults to STRICT policy with 'self' sources.
 *
 * ## Quick Start
 *
 * ```php
 * // Production (strict, nonce-based)
 * $csp = CspDirectives::strict();
 *
 * // Development (lenient, with hot reload)
 * $csp = CspDirectives::development('localhost:5173');
 *
 * // Legacy apps (unsafe-inline/eval allowed)
 * $csp = CspDirectives::legacy();
 * ```
 *
 * ## Fluent API
 *
 * ```php
 * $csp = CspDirectives::strict()
 *     ->withImgSrc("'self' https://cdn.example.com")
 *     ->withFontSrc("'self' https://fonts.gstatic.com")
 *     ->withReportUri('/csp-violations');
 * ```
 *
 * @see HeaderBuilder::build() To generate the CSP header string
 * @see NonceProvider::get() To get the nonce for inline scripts/styles
 */
final readonly class CspDirectives
{
    use ValidatesDirectiveValues;

    /**
     * @param string $defaultSrc Default source for all fetch directives
     * @param string|null $scriptSrc Script sources (null = auto-generate with nonce)
     * @param string|null $styleSrc Style sources (null = auto-generate with nonce)
     * @param ResourceDirectives $resources Resource fetch directives (img, font, connect, media, worker, child, manifest)
     * @param NavigationDirectives $navigation Document navigation directives (frame-ancestors, base-uri, form-action)
     * @param string|null $websocketHost WebSocket host (adds wss:// and https:// to connect-src)
     * @param SecurityPolicy $securityPolicy Security policy level (controls unsafe-* directives)
     * @param ReportingConfig $reporting Reporting and security upgrade configuration
     */
    public function __construct(
        public string $defaultSrc = "'self'",
        public ?string $scriptSrc = null,
        public ?string $styleSrc = null,
        public ResourceDirectives $resources = new ResourceDirectives(),
        public NavigationDirectives $navigation = new NavigationDirectives(),
        public ?string $websocketHost = null,
        public SecurityPolicy $securityPolicy = SecurityPolicy::STRICT,
        public ReportingConfig $reporting = new ReportingConfig(),
    ) {
        $this->validate();
    }

    // =========================================================================
    // Factory Methods
    // =========================================================================

    /**
     * Create strict CSP configuration for production
     *
     * Uses nonce-based script/style loading with strict-dynamic.
     * No unsafe-eval, no unsafe-inline. Recommended for production.
     *
     * ```php
     * $csp = CspDirectives::strict()
     *     ->withImgSrc("'self' https://cdn.example.com")
     *     ->withReportUri('/csp-violations');
     *
     * header('Content-Security-Policy: ' . HeaderBuilder::build($csp));
     * ```
     */
    public static function strict(): self
    {
        return new self(securityPolicy: SecurityPolicy::STRICT);
    }

    /**
     * Create lenient CSP configuration for development
     *
     * Allows unsafe-eval and unsafe-inline for development tools.
     * Optionally configures WebSocket for hot module replacement (HMR).
     *
     * ```php
     * // Vite dev server
     * $csp = CspDirectives::development('localhost:5173');
     *
     * // Webpack dev server on custom IP
     * $csp = CspDirectives::development('192.168.1.100:8080');
     *
     * // Without hot reload
     * $csp = CspDirectives::development();
     * ```
     *
     * @param string|null $hotReloadHost WebSocket host for HMR (e.g., 'localhost:5173')
     */
    public static function development(?string $hotReloadHost = null): self
    {
        $directives = new self(securityPolicy: SecurityPolicy::LENIENT);

        if ($hotReloadHost !== null) {
            return $directives->withWebSocket($hotReloadHost);
        }

        return $directives;
    }

    /**
     * Create CSP configuration for legacy applications
     *
     * Allows unsafe-eval for frameworks like Vue 2, older Angular versions.
     * Still enforces nonce-based inline scripts/styles where possible.
     *
     * ```php
     * // Vue 2 / Angular 1.x application
     * $csp = CspDirectives::legacy()
     *     ->withImgSrc("'self' data:")
     *     ->withFontSrc("'self' https://fonts.gstatic.com");
     * ```
     */
    public static function legacy(): self
    {
        return new self(securityPolicy: SecurityPolicy::UNSAFE_EVAL);
    }

    // =========================================================================
    // Fluent API (with* methods)
    // =========================================================================

    /**
     * Create new instance with modified default-src
     *
     * @psalm-api
     */
    public function withDefaultSrc(string $value): self
    {
        return $this->cloneWith(defaultSrc: $value);
    }

    /**
     * Create new instance with modified script-src
     */
    public function withScriptSrc(string $value): self
    {
        return $this->cloneWith(scriptSrc: $value);
    }

    /**
     * Create new instance with modified style-src
     *
     * @psalm-api
     */
    public function withStyleSrc(string $value): self
    {
        return $this->cloneWith(styleSrc: $value);
    }

    /**
     * Create new instance with modified img-src
     */
    public function withImgSrc(string $value): self
    {
        return $this->cloneWith(resources: $this->resources->withImg($value));
    }

    /**
     * Create new instance with modified font-src
     */
    public function withFontSrc(string $value): self
    {
        return $this->cloneWith(resources: $this->resources->withFont($value));
    }

    /**
     * Create new instance with modified connect-src
     *
     * @psalm-api
     */
    public function withConnectSrc(string $value): self
    {
        return $this->cloneWith(resources: $this->resources->withConnect($value));
    }

    /**
     * Create new instance with modified resource directives
     *
     * @psalm-api
     */
    public function withResources(ResourceDirectives $resources): self
    {
        return $this->cloneWith(resources: $resources);
    }

    /**
     * Create new instance with modified navigation directives
     *
     * @psalm-api
     */
    public function withNavigation(NavigationDirectives $navigation): self
    {
        return $this->cloneWith(navigation: $navigation);
    }

    /**
     * Create new instance with WebSocket host
     *
     * Adds wss://host and https://host to connect-src directive.
     * Use for both development (hot reload) and production (real-time features).
     */
    public function withWebSocket(string $host): self
    {
        return $this->cloneWith(websocketHost: $host);
    }

    /**
     * Create new instance with modified frame-ancestors
     *
     * @psalm-api
     */
    public function withFrameAncestors(string $value): self
    {
        return $this->cloneWith(navigation: $this->navigation->withFrameAncestors($value));
    }

    /**
     * Create new instance with modified base-uri
     *
     * @psalm-api
     */
    public function withBaseUri(string $value): self
    {
        return $this->cloneWith(navigation: $this->navigation->withBaseUri($value));
    }

    /**
     * Create new instance with modified form-action
     *
     * @psalm-api
     */
    public function withFormAction(string $value): self
    {
        return $this->cloneWith(navigation: $this->navigation->withFormAction($value));
    }

    /**
     * Create new instance with modified security policy
     *
     * @psalm-api
     */
    public function withSecurityPolicy(SecurityPolicy $policy): self
    {
        return $this->cloneWith(securityPolicy: $policy);
    }

    /**
     * Create new instance with modified reporting configuration
     *
     * @psalm-api
     */
    public function withReporting(ReportingConfig $reporting): self
    {
        return $this->cloneWith(reporting: $reporting);
    }

    /**
     * Create a clone with specified property overrides
     */
    private function cloneWith(
        ?string $defaultSrc = null,
        ?string $scriptSrc = null,
        ?string $styleSrc = null,
        ?ResourceDirectives $resources = null,
        ?NavigationDirectives $navigation = null,
        ?string $websocketHost = null,
        ?SecurityPolicy $securityPolicy = null,
        ?ReportingConfig $reporting = null,
    ): self {
        return new self(
            defaultSrc: $defaultSrc ?? $this->defaultSrc,
            scriptSrc: $scriptSrc ?? $this->scriptSrc,
            styleSrc: $styleSrc ?? $this->styleSrc,
            resources: $resources ?? $this->resources,
            navigation: $navigation ?? $this->navigation,
            websocketHost: $websocketHost ?? $this->websocketHost,
            securityPolicy: $securityPolicy ?? $this->securityPolicy,
            reporting: $reporting ?? $this->reporting,
        );
    }

    /**
     * Create new instance with modified upgrade-insecure-requests
     *
     * Convenience method - delegates to ReportingConfig
     *
     * @psalm-api
     */
    public function withUpgradeInsecure(bool $enabled): self
    {
        return $this->withReporting($this->reporting->withUpgradeInsecure($enabled));
    }

    /**
     * Create new instance with report-uri
     *
     * Convenience method - delegates to ReportingConfig
     *
     * @psalm-api
     */
    public function withReportUri(string $uri): self
    {
        return $this->withReporting($this->reporting->withUri($uri));
    }

    /**
     * Create new instance with report-to endpoint
     *
     * Convenience method - delegates to ReportingConfig
     *
     * @psalm-api
     */
    public function withReportTo(string $endpoint): self
    {
        return $this->withReporting($this->reporting->withEndpoint($endpoint));
    }

    /**
     * Convert directives to CSP header value
     *
     * Automatically injects nonce into script-src and style-src if not explicitly set.
     *
     * @param string $nonce Base64-encoded nonce value
     * @return string Complete CSP header value
     */
    public function toHeaderValue(string $nonce): string
    {
        return (new HeaderValueBuilder($this, $nonce))->build();
    }

    /**
     * Validate configuration
     *
     * @throws InvalidArgumentException If configuration is invalid
     * @throws InvalidDirectiveValueException If directive values contain injection characters
     */
    private function validate(): void
    {
        // Validate default-src is not empty (required by CSP spec)
        if (trim($this->defaultSrc) === '') {
            throw new InvalidArgumentException('default-src cannot be empty');
        }

        // Validate directive values for injection attacks
        $this->validateDirectiveValue('default-src', $this->defaultSrc);
        if ($this->scriptSrc !== null) {
            $this->validateDirectiveValue('script-src', $this->scriptSrc);
        }

        if ($this->styleSrc !== null) {
            $this->validateDirectiveValue('style-src', $this->styleSrc);
        }

        // Validate WebSocket host format and port range (supports IPv4, IPv6, and hostnames)
        if ($this->websocketHost !== null) {
            // Match: hostname:port, IPv4:port, or [IPv6]:port (including IPv4-mapped IPv6 like [::ffff:192.168.1.1])
            if (!preg_match('/^(?:\[[a-f0-9:.]+\]|[a-z0-9.-]+):(\d+)$/i', $this->websocketHost, $matches)) {
                throw InvalidDirectiveValueException::invalidWebSocketHost($this->websocketHost);
            }

            $port = (int) $matches[1];
            if ($port < 1 || $port > 65535) {
                throw InvalidDirectiveValueException::invalidWebSocketPort($this->websocketHost, $port);
            }
        }

        // Note: ReportingConfig validates its own values in constructor

        // Warn on policy conflicts (after validation passes)
        $this->warnOnPolicyConflict();
    }

    /**
     * Emit warnings for policy conflicts
     *
     * Warns when STRICT policy is used with unsafe-* directives in custom sources.
     * These combinations weaken the security benefits of STRICT policy.
     */
    private function warnOnPolicyConflict(): void
    {
        if ($this->securityPolicy !== SecurityPolicy::STRICT) {
            return;
        }

        // Check script-src for unsafe directives
        if ($this->scriptSrc !== null) {
            if (str_contains($this->scriptSrc, "'unsafe-inline'")) {
                trigger_error(
                    "CSP policy conflict: STRICT policy with 'unsafe-inline' in script-src weakens XSS protection",
                    E_USER_WARNING
                );
            }

            if (str_contains($this->scriptSrc, "'unsafe-eval'")) {
                trigger_error(
                    "CSP policy conflict: STRICT policy with 'unsafe-eval' in script-src weakens XSS protection",
                    E_USER_WARNING
                );
            }
        }

        // Check style-src for unsafe-inline
        if ($this->styleSrc !== null && str_contains($this->styleSrc, "'unsafe-inline'")) {
            trigger_error(
                "CSP policy conflict: STRICT policy with 'unsafe-inline' in style-src weakens protection",
                E_USER_WARNING
            );
        }
    }
}
