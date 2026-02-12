<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Builder;

use Random\RandomException;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\HeaderBuilder;
use Zappzarapp\Security\Csp\HeaderBuilder as CspHeaderBuilder;
use Zappzarapp\Security\Headers\Coep\CoepValue;
use Zappzarapp\Security\Headers\Coop\CoopValue;
use Zappzarapp\Security\Headers\Corp\CorpValue;
use Zappzarapp\Security\Headers\Hsts\HstsConfig;
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionsPolicy;
use Zappzarapp\Security\Headers\ReferrerPolicy\ReferrerPolicyValue;
use Zappzarapp\Security\Headers\SecurityHeaders;
use Zappzarapp\Security\Headers\XFrameOptions\XFrameOptionsValue;

/**
 * Builder for converting SecurityHeaders to header arrays or applying directly
 *
 * @see SecurityHeaders Immutable aggregate of all security headers
 */
final readonly class SecurityHeadersBuilder
{
    private const string HEADER_HSTS                   = 'Strict-Transport-Security';

    private const string HEADER_COOP                   = 'Cross-Origin-Opener-Policy';

    private const string HEADER_COEP                   = 'Cross-Origin-Embedder-Policy';

    private const string HEADER_CORP                   = 'Cross-Origin-Resource-Policy';

    private const string HEADER_REFERRER_POLICY        = 'Referrer-Policy';

    private const string HEADER_X_FRAME_OPTIONS        = 'X-Frame-Options';

    private const string HEADER_PERMISSIONS_POLICY     = 'Permissions-Policy';

    private const string HEADER_X_CONTENT_TYPE_OPTIONS = 'X-Content-Type-Options';

    private const string HEADER_X_XSS_PROTECTION       = 'X-XSS-Protection';

    private const string HEADER_CSP                    = 'Content-Security-Policy';

    public function __construct(
        private SecurityHeaders $headers,
        private ?CspHeaderBuilder $cspBuilder = null,
    ) {
    }

    /**
     * Build header array (name => value)
     *
     * @return array<string, string>
     *
     * @throws RandomException If CSP is configured and nonce generation fails
     */
    public function build(): array
    {
        $result = [];

        if ($this->headers->hsts instanceof HstsConfig) {
            $result[self::HEADER_HSTS] = $this->headers->hsts->headerValue();
        }

        if ($this->headers->coop instanceof CoopValue) {
            $result[self::HEADER_COOP] = $this->headers->coop->headerValue();
        }

        if ($this->headers->coep instanceof CoepValue) {
            $result[self::HEADER_COEP] = $this->headers->coep->headerValue();
        }

        if ($this->headers->corp instanceof CorpValue) {
            $result[self::HEADER_CORP] = $this->headers->corp->headerValue();
        }

        if ($this->headers->referrerPolicy instanceof ReferrerPolicyValue) {
            $result[self::HEADER_REFERRER_POLICY] = $this->headers->referrerPolicy->headerValue();
        }

        if ($this->headers->xFrameOptions instanceof XFrameOptionsValue) {
            $result[self::HEADER_X_FRAME_OPTIONS] = $this->headers->xFrameOptions->headerValue();
        }

        if ($this->headers->permissionsPolicy instanceof PermissionsPolicy) {
            $value = $this->headers->permissionsPolicy->headerValue();
            if ($value !== '') {
                $result[self::HEADER_PERMISSIONS_POLICY] = $value;
            }
        }

        if ($this->headers->xContentTypeOptions) {
            $result[self::HEADER_X_CONTENT_TYPE_OPTIONS] = 'nosniff';
        }

        if ($this->headers->xXssProtection) {
            // XSS filter causes security issues in modern browsers; disable it
            // See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
            $result[self::HEADER_X_XSS_PROTECTION] = '0';
        }

        // Handle CSP
        if ($this->headers->csp instanceof CspDirectives && $this->cspBuilder instanceof HeaderBuilder) {
            $result[self::HEADER_CSP] = $this->cspBuilder->build($this->headers->csp);
        }

        return $result;
    }

    /**
     * Apply headers using header() function
     *
     * @param bool $replace Replace existing headers with same name
     *
     * @throws RandomException If CSP is configured and nonce generation fails
     *
     * @codeCoverageIgnore Uses header() which cannot be tested in PHPUnit
     */
    public function apply(bool $replace = true): void
    {
        foreach ($this->build() as $name => $value) {
            header($name . ': ' . $value, $replace);
        }
    }

    /**
     * Create builder from SecurityHeaders
     */
    public static function from(SecurityHeaders $headers, ?CspHeaderBuilder $cspBuilder = null): self
    {
        return new self($headers, $cspBuilder);
    }
}
