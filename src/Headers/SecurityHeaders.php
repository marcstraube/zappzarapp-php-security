<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers;

use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Headers\Coep\CoepValue;
use Zappzarapp\Security\Headers\Coop\CoopValue;
use Zappzarapp\Security\Headers\Corp\CorpValue;
use Zappzarapp\Security\Headers\Hsts\HstsConfig;
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionsPolicy;
use Zappzarapp\Security\Headers\ReferrerPolicy\ReferrerPolicyValue;
use Zappzarapp\Security\Headers\XFrameOptions\XFrameOptionsValue;

/**
 * Immutable aggregate of all security headers
 *
 * Combines all HTTP security headers into a single configuration object.
 * Use the builder or factory methods to create instances.
 *
 * @see SecurityHeadersBuilder For fluent construction
 */
final readonly class SecurityHeaders
{
    /**
     * @param HstsConfig|null $hsts HSTS configuration (null = header not set)
     * @param CoopValue|null $coop Cross-Origin-Opener-Policy (null = header not set)
     * @param CoepValue|null $coep Cross-Origin-Embedder-Policy (null = header not set)
     * @param CorpValue|null $corp Cross-Origin-Resource-Policy (null = header not set)
     * @param ReferrerPolicyValue|null $referrerPolicy Referrer-Policy (null = header not set)
     * @param XFrameOptionsValue|null $xFrameOptions X-Frame-Options (null = header not set)
     * @param PermissionsPolicy|null $permissionsPolicy Permissions-Policy (null = header not set)
     * @param CspDirectives|null $csp CSP configuration from CSP module (null = header not set)
     * @param bool $xContentTypeOptions Send X-Content-Type-Options: nosniff
     * @param bool $xXssProtection Send X-XSS-Protection: 0 (disable legacy filter)
     */
    public function __construct(
        public ?HstsConfig $hsts = null,
        public ?CoopValue $coop = null,
        public ?CoepValue $coep = null,
        public ?CorpValue $corp = null,
        public ?ReferrerPolicyValue $referrerPolicy = null,
        public ?XFrameOptionsValue $xFrameOptions = null,
        public ?PermissionsPolicy $permissionsPolicy = null,
        public ?CspDirectives $csp = null,
        public bool $xContentTypeOptions = true,
        public bool $xXssProtection = true,
    ) {
    }

    /**
     * Create with HSTS configuration
     */
    public function withHsts(HstsConfig $hsts): self
    {
        return $this->cloneWith(hsts: $hsts);
    }

    /**
     * Create without HSTS header
     */
    public function withoutHsts(): self
    {
        return $this->cloneWith(hsts: false);
    }

    /**
     * Create with COOP value
     */
    public function withCoop(CoopValue $coop): self
    {
        return $this->cloneWith(coop: $coop);
    }

    /**
     * Create without COOP header
     */
    public function withoutCoop(): self
    {
        return $this->cloneWith(coop: false);
    }

    /**
     * Create with COEP value
     */
    public function withCoep(CoepValue $coep): self
    {
        return $this->cloneWith(coep: $coep);
    }

    /**
     * Create without COEP header
     */
    public function withoutCoep(): self
    {
        return $this->cloneWith(coep: false);
    }

    /**
     * Create with CORP value
     */
    public function withCorp(CorpValue $corp): self
    {
        return $this->cloneWith(corp: $corp);
    }

    /**
     * Create without CORP header
     */
    public function withoutCorp(): self
    {
        return $this->cloneWith(corp: false);
    }

    /**
     * Create with Referrer-Policy value
     */
    public function withReferrerPolicy(ReferrerPolicyValue $referrerPolicy): self
    {
        return $this->cloneWith(referrerPolicy: $referrerPolicy);
    }

    /**
     * Create without Referrer-Policy header
     */
    public function withoutReferrerPolicy(): self
    {
        return $this->cloneWith(referrerPolicy: false);
    }

    /**
     * Create with X-Frame-Options value
     */
    public function withXFrameOptions(XFrameOptionsValue $xFrameOptions): self
    {
        return $this->cloneWith(xFrameOptions: $xFrameOptions);
    }

    /**
     * Create without X-Frame-Options header
     */
    public function withoutXFrameOptions(): self
    {
        return $this->cloneWith(xFrameOptions: false);
    }

    /**
     * Create with Permissions-Policy
     */
    public function withPermissionsPolicy(PermissionsPolicy $permissionsPolicy): self
    {
        return $this->cloneWith(permissionsPolicy: $permissionsPolicy);
    }

    /**
     * Create without Permissions-Policy header
     */
    public function withoutPermissionsPolicy(): self
    {
        return $this->cloneWith(permissionsPolicy: false);
    }

    /**
     * Create with CSP configuration
     */
    public function withCsp(CspDirectives $csp): self
    {
        return $this->cloneWith(csp: $csp);
    }

    /**
     * Create without CSP header
     */
    public function withoutCsp(): self
    {
        return $this->cloneWith(csp: false);
    }

    /**
     * Create with X-Content-Type-Options enabled
     */
    public function withXContentTypeOptions(): self
    {
        return $this->cloneWith(xContentTypeOptions: true);
    }

    /**
     * Create with X-Content-Type-Options disabled
     */
    public function withoutXContentTypeOptions(): self
    {
        return $this->cloneWith(xContentTypeOptions: false);
    }

    /**
     * Create with X-XSS-Protection enabled (sends header with value "0")
     */
    public function withXXssProtection(): self
    {
        return $this->cloneWith(xXssProtection: true);
    }

    /**
     * Create with X-XSS-Protection disabled (no header)
     */
    public function withoutXXssProtection(): self
    {
        return $this->cloneWith(xXssProtection: false);
    }

    /**
     * Clone with specific property overrides
     *
     * Uses false as sentinel to set nullable properties to null.
     */
    private function cloneWith(
        mixed $hsts = null,
        mixed $coop = null,
        mixed $coep = null,
        mixed $corp = null,
        mixed $referrerPolicy = null,
        mixed $xFrameOptions = null,
        mixed $permissionsPolicy = null,
        mixed $csp = null,
        ?bool $xContentTypeOptions = null,
        ?bool $xXssProtection = null,
    ): self {
        return new self(
            hsts: $hsts === false ? null : ($hsts ?? $this->hsts),
            coop: $coop === false ? null : ($coop ?? $this->coop),
            coep: $coep === false ? null : ($coep ?? $this->coep),
            corp: $corp === false ? null : ($corp ?? $this->corp),
            referrerPolicy: $referrerPolicy === false ? null : ($referrerPolicy ?? $this->referrerPolicy),
            xFrameOptions: $xFrameOptions === false ? null : ($xFrameOptions ?? $this->xFrameOptions),
            permissionsPolicy: $permissionsPolicy === false ? null : ($permissionsPolicy ?? $this->permissionsPolicy),
            csp: $csp === false ? null : ($csp ?? $this->csp),
            xContentTypeOptions: $xContentTypeOptions ?? $this->xContentTypeOptions,
            xXssProtection: $xXssProtection ?? $this->xXssProtection,
        );
    }

    /**
     * Create strict security headers (maximum protection)
     *
     * Recommended for web applications handling sensitive data.
     *
     * Includes:
     * - HSTS: 2 years, includeSubDomains
     * - X-Frame-Options: DENY
     * - X-Content-Type-Options: enabled
     * - Referrer-Policy: strict-origin-when-cross-origin
     * - X-XSS-Protection: disabled (causes issues in modern browsers)
     * - COEP: require-corp
     * - COOP: same-origin
     * - CORP: same-origin
     */
    public static function strict(): self
    {
        return new self(
            hsts: HstsConfig::strict(),
            coop: CoopValue::SAME_ORIGIN,
            coep: CoepValue::REQUIRE_CORP,
            corp: CorpValue::SAME_ORIGIN,
            referrerPolicy: ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
            xFrameOptions: XFrameOptionsValue::DENY,
            permissionsPolicy: PermissionsPolicy::strict(),
            xContentTypeOptions: true,
            xXssProtection: false
        );
    }

    /**
     * Create moderate security headers (balanced protection)
     *
     * Good default for most web applications.
     *
     * Includes:
     * - HSTS: 1 year
     * - X-Frame-Options: SAMEORIGIN
     * - X-Content-Type-Options: enabled
     * - Referrer-Policy: strict-origin-when-cross-origin
     */
    public static function moderate(): self
    {
        return new self(
            hsts: new HstsConfig(maxAge: 31536000, includeSubDomains: false, preload: false),
            coop: null,
            coep: null,
            corp: null,
            referrerPolicy: ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
            xFrameOptions: XFrameOptionsValue::SAMEORIGIN,
            permissionsPolicy: null,
            xContentTypeOptions: true,
            xXssProtection: true
        );
    }

    /**
     * Create legacy configuration (maximum compatibility)
     *
     * Minimal security headers for legacy browser support.
     * Not recommended for new applications.
     */
    public static function legacy(): self
    {
        return new self(
            hsts: HstsConfig::strict(),
            coop: null,
            coep: null,
            corp: null,
            referrerPolicy: ReferrerPolicyValue::NO_REFERRER_WHEN_DOWNGRADE,
            xFrameOptions: XFrameOptionsValue::SAMEORIGIN,
            permissionsPolicy: null,
            xContentTypeOptions: true,
            xXssProtection: true
        );
    }

    /**
     * Create development configuration (minimal restrictions)
     *
     * For local development only. Not secure for production.
     */
    public static function development(): self
    {
        return new self(
            hsts: null,
            coop: null,
            coep: null,
            corp: null,
            referrerPolicy: null,
            xFrameOptions: null,
            permissionsPolicy: null,
            xContentTypeOptions: true,
            xXssProtection: true
        );
    }

    /**
     * Create API security headers (for REST/GraphQL APIs)
     *
     * Optimized for API responses (no framing concerns).
     *
     * Includes:
     * - HSTS: 2 years, includeSubDomains
     * - X-Content-Type-Options: enabled
     * - CORP: same-origin
     * - No X-Frame-Options (not relevant for APIs)
     */
    public static function api(): self
    {
        return new self(
            hsts: HstsConfig::strict(),
            coop: null,
            coep: null,
            corp: CorpValue::SAME_ORIGIN,
            referrerPolicy: null,
            xFrameOptions: null,
            permissionsPolicy: null,
            xContentTypeOptions: true,
            xXssProtection: true
        );
    }
}
