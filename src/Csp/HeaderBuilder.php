<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp;

use Random\RandomException;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;
use Zappzarapp\Security\Csp\Nonce\NonceProvider;

/**
 * CSP Header Builder
 *
 * Builds Content-Security-Policy headers with nonce support.
 * Supports both enforcement and report-only modes.
 *
 * ## Basic Usage
 *
 * ```php
 * use Zappzarapp\Security\Csp\HeaderBuilder;
 * use Zappzarapp\Security\Csp\CspDirectives;
 *
 * // Build CSP header value
 * $csp = HeaderBuilder::build(CspDirectives::strict());
 * header("Content-Security-Policy: {$csp}");
 *
 * // Or use buildHeader() for complete header string
 * header(HeaderBuilder::buildHeader(CspDirectives::strict()));
 * ```
 *
 * ## Report-Only Mode (Testing)
 *
 * ```php
 * // Test new policy without blocking violations
 * header(HeaderBuilder::buildReportOnlyHeader(
 *     CspDirectives::strict()->withReportUri('/csp-violations')
 * ));
 * ```
 *
 * ## Testing with NullNonce
 *
 * ```php
 * // Disable nonce generation for integration tests
 * $csp = HeaderBuilder::build(CspDirectives::strict(), new NullNonce());
 * ```
 */
final class HeaderBuilder
{
    public const string HEADER_CSP             = 'Content-Security-Policy';

    public const string HEADER_CSP_REPORT_ONLY = 'Content-Security-Policy-Report-Only';

    /**
     * Build CSP header value
     *
     * @param CspDirectives $directives CSP configuration
     * @param NonceProvider|null $nonceProvider Nonce provider (null = use NonceGenerator)
     * @return string Complete CSP header value
     * @throws RandomException If no suitable random source is available
     */
    public static function build(CspDirectives $directives, ?NonceProvider $nonceProvider = null): string
    {
        $provider = $nonceProvider ?? new NonceGenerator();

        return $directives->toHeaderValue($provider->get());
    }

    /**
     * Get enforced header name
     */
    public static function getHeaderName(): string
    {
        return self::HEADER_CSP;
    }

    /**
     * Get report-only header name
     */
    public static function getReportOnlyHeaderName(): string
    {
        return self::HEADER_CSP_REPORT_ONLY;
    }

    /**
     * Build complete enforced header string
     *
     * @param CspDirectives $directives CSP configuration
     * @param NonceProvider|null $nonceProvider Nonce provider (null = use NonceGenerator)
     * @return string Complete header string (e.g., "Content-Security-Policy: ...")
     * @throws RandomException If no suitable random source is available
     */
    public static function buildHeader(
        CspDirectives $directives,
        ?NonceProvider $nonceProvider = null
    ): string {
        return sprintf('%s: %s', self::HEADER_CSP, self::build($directives, $nonceProvider));
    }

    /**
     * Build complete report-only header string (violations logged, not blocked)
     *
     * @param CspDirectives $directives CSP configuration
     * @param NonceProvider|null $nonceProvider Nonce provider (null = use NonceGenerator)
     * @return string Complete header string (e.g., "Content-Security-Policy-Report-Only: ...")
     * @throws RandomException If no suitable random source is available
     */
    public static function buildReportOnlyHeader(
        CspDirectives $directives,
        ?NonceProvider $nonceProvider = null
    ): string {
        return sprintf('%s: %s', self::HEADER_CSP_REPORT_ONLY, self::build($directives, $nonceProvider));
    }
}
