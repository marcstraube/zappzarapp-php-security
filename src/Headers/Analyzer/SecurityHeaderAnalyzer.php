<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Analyzer;

/**
 * Analyzes HTTP response headers for security issues
 *
 * Inspects headers for missing, weak, or misconfigured security headers
 * and returns structured findings with actionable recommendations.
 */
final class SecurityHeaderAnalyzer
{
    private const int HSTS_MIN_MAX_AGE = 31_536_000;

    /**
     * Analyze response headers for security issues
     *
     * @param array<string, string> $headers Header name => value map (case-insensitive matching)
     */
    public function analyze(array $headers): AnalysisResult
    {
        $normalized = $this->normalizeHeaders($headers);

        $findings = [
            ...$this->analyzeHsts($normalized),
            ...$this->analyzeCsp($normalized),
            ...$this->analyzeXFrameOptions($normalized),
            ...$this->analyzeXContentTypeOptions($normalized),
            ...$this->analyzeReferrerPolicy($normalized),
            ...$this->analyzePermissionsPolicy($normalized),
            ...$this->analyzeCoop($normalized),
            ...$this->analyzeCoep($normalized),
            ...$this->analyzeCorp($normalized),
        ];

        return new AnalysisResult(...$findings);
    }

    /**
     * @param array<string, string> $headers
     *
     * @return list<Finding>
     */
    private function analyzeHsts(array $headers): array
    {
        $findings = [];
        $value    = $headers['strict-transport-security'] ?? null;

        if ($value === null) {
            $findings[] = new Finding(
                'Strict-Transport-Security',
                FindingSeverity::HIGH,
                'HSTS header is missing',
                'Add Strict-Transport-Security header with max-age of at least 1 year and includeSubDomains',
            );

            return $findings;
        }

        if (preg_match('/max-age=(\d+)/i', $value, $matches)) {
            $maxAge = (int) $matches[1];

            if ($maxAge < self::HSTS_MIN_MAX_AGE) {
                $findings[] = new Finding(
                    'Strict-Transport-Security',
                    FindingSeverity::MEDIUM,
                    sprintf('HSTS max-age is %d seconds, recommended minimum is %d (1 year)', $maxAge, self::HSTS_MIN_MAX_AGE),
                    'Increase max-age to at least 31536000 (1 year), ideally 63072000 (2 years)',
                );
            }
        }

        if (!str_contains(strtolower($value), 'includesubdomains')) {
            $findings[] = new Finding(
                'Strict-Transport-Security',
                FindingSeverity::MEDIUM,
                'HSTS header is missing includeSubDomains directive',
                'Add includeSubDomains to protect all subdomains',
            );
        }

        return $findings;
    }

    /**
     * @param array<string, string> $headers
     *
     * @return list<Finding>
     */
    private function analyzeCsp(array $headers): array
    {
        $findings = [];
        $value    = $headers['content-security-policy'] ?? null;

        if ($value === null) {
            $findings[] = new Finding(
                'Content-Security-Policy',
                FindingSeverity::HIGH,
                'CSP header is missing',
                'Add a Content-Security-Policy header to prevent XSS and data injection attacks',
            );

            return $findings;
        }

        $directives = $this->parseCspDirectives($value);

        if (!isset($directives['default-src'])) {
            $findings[] = new Finding(
                'Content-Security-Policy',
                FindingSeverity::MEDIUM,
                'CSP is missing default-src directive',
                'Add default-src as a fallback for other fetch directives',
            );
        }

        $scriptSrc = $directives['script-src'] ?? $directives['default-src'] ?? '';

        if (str_contains($scriptSrc, "'unsafe-inline'")) {
            $findings[] = new Finding(
                'Content-Security-Policy',
                FindingSeverity::HIGH,
                "CSP allows 'unsafe-inline' in script-src, enabling inline script execution",
                "Remove 'unsafe-inline' from script-src and use nonce-based or hash-based CSP instead",
            );
        }

        if (str_contains($scriptSrc, "'unsafe-eval'")) {
            $findings[] = new Finding(
                'Content-Security-Policy',
                FindingSeverity::HIGH,
                "CSP allows 'unsafe-eval' in script-src, enabling eval() and similar functions",
                "Remove 'unsafe-eval' from script-src and refactor code to avoid eval()",
            );
        }

        $styleSrc = $directives['style-src'] ?? $directives['default-src'] ?? '';

        if (str_contains($styleSrc, "'unsafe-inline'")) {
            $findings[] = new Finding(
                'Content-Security-Policy',
                FindingSeverity::MEDIUM,
                "CSP allows 'unsafe-inline' in style-src",
                "Consider removing 'unsafe-inline' from style-src and use nonce-based or hash-based CSP for styles",
            );
        }

        foreach ($directives as $directive => $sources) {
            if (preg_match('/(?:^|\s)\*(?:\s|$)/', $sources) && $directive !== 'report-uri') {
                $findings[] = new Finding(
                    'Content-Security-Policy',
                    FindingSeverity::HIGH,
                    sprintf("CSP directive '%s' uses wildcard (*) source, allowing any origin", $directive),
                    sprintf("Replace wildcard in '%s' with specific trusted origins", $directive),
                );
            }
        }

        return $findings;
    }

    /**
     * @param array<string, string> $headers
     *
     * @return list<Finding>
     */
    private function analyzeXFrameOptions(array $headers): array
    {
        if (!isset($headers['x-frame-options'])) {
            return [new Finding(
                'X-Frame-Options',
                FindingSeverity::MEDIUM,
                'X-Frame-Options header is missing',
                'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking, or use CSP frame-ancestors',
            )];
        }

        return [];
    }

    /**
     * @param array<string, string> $headers
     *
     * @return list<Finding>
     */
    private function analyzeXContentTypeOptions(array $headers): array
    {
        $value = $headers['x-content-type-options'] ?? null;

        if ($value === null) {
            return [new Finding(
                'X-Content-Type-Options',
                FindingSeverity::MEDIUM,
                'X-Content-Type-Options header is missing',
                'Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing',
            )];
        }

        if (strtolower(trim($value)) !== 'nosniff') {
            return [new Finding(
                'X-Content-Type-Options',
                FindingSeverity::MEDIUM,
                sprintf('X-Content-Type-Options has invalid value "%s"', $value),
                'Set X-Content-Type-Options to "nosniff" (the only valid value)',
            )];
        }

        return [];
    }

    /**
     * @param array<string, string> $headers
     *
     * @return list<Finding>
     */
    private function analyzeReferrerPolicy(array $headers): array
    {
        $value = $headers['referrer-policy'] ?? null;

        if ($value === null) {
            return [new Finding(
                'Referrer-Policy',
                FindingSeverity::LOW,
                'Referrer-Policy header is missing',
                'Add Referrer-Policy: strict-origin-when-cross-origin for a good balance of security and functionality',
            )];
        }

        $policy = strtolower(trim($value));

        if ($policy === 'unsafe-url') {
            return [new Finding(
                'Referrer-Policy',
                FindingSeverity::HIGH,
                'Referrer-Policy is set to "unsafe-url", leaking full URLs to all origins',
                'Change Referrer-Policy to "strict-origin-when-cross-origin" or "no-referrer"',
            )];
        }

        if ($policy === 'no-referrer-when-downgrade') {
            return [new Finding(
                'Referrer-Policy',
                FindingSeverity::LOW,
                'Referrer-Policy "no-referrer-when-downgrade" leaks full URL on same-protocol navigations',
                'Consider using "strict-origin-when-cross-origin" for better privacy',
            )];
        }

        return [];
    }

    /**
     * @param array<string, string> $headers
     *
     * @return list<Finding>
     */
    private function analyzePermissionsPolicy(array $headers): array
    {
        if (!isset($headers['permissions-policy'])) {
            return [new Finding(
                'Permissions-Policy',
                FindingSeverity::LOW,
                'Permissions-Policy header is missing',
                'Add Permissions-Policy to restrict browser feature access (camera, microphone, geolocation, etc.)',
            )];
        }

        return [];
    }

    /**
     * @param array<string, string> $headers
     *
     * @return list<Finding>
     */
    private function analyzeCoop(array $headers): array
    {
        if (!isset($headers['cross-origin-opener-policy'])) {
            return [new Finding(
                'Cross-Origin-Opener-Policy',
                FindingSeverity::LOW,
                'COOP header is missing',
                'Add Cross-Origin-Opener-Policy: same-origin to isolate your browsing context',
            )];
        }

        return [];
    }

    /**
     * @param array<string, string> $headers
     *
     * @return list<Finding>
     */
    private function analyzeCoep(array $headers): array
    {
        if (!isset($headers['cross-origin-embedder-policy'])) {
            return [new Finding(
                'Cross-Origin-Embedder-Policy',
                FindingSeverity::INFO,
                'COEP header is missing',
                'Add Cross-Origin-Embedder-Policy: require-corp if cross-origin isolation is needed',
            )];
        }

        return [];
    }

    /**
     * @param array<string, string> $headers
     *
     * @return list<Finding>
     */
    private function analyzeCorp(array $headers): array
    {
        if (!isset($headers['cross-origin-resource-policy'])) {
            return [new Finding(
                'Cross-Origin-Resource-Policy',
                FindingSeverity::INFO,
                'CORP header is missing',
                'Add Cross-Origin-Resource-Policy: same-origin to prevent cross-origin reads of your resources',
            )];
        }

        return [];
    }

    /**
     * Normalize header names to lowercase for case-insensitive matching
     *
     * @param array<string, string> $headers
     *
     * @return array<string, string>
     */
    private function normalizeHeaders(array $headers): array
    {
        $normalized = [];

        foreach ($headers as $name => $value) {
            $normalized[strtolower($name)] = $value;
        }

        return $normalized;
    }

    /**
     * Parse CSP header value into directive => sources map
     *
     * @return array<string, string>
     */
    private function parseCspDirectives(string $csp): array
    {
        $directives = [];

        foreach (explode(';', $csp) as $part) {
            $part = trim($part);

            if ($part === '') {
                continue;
            }

            $spacePos = strpos($part, ' ');

            if ($spacePos === false) {
                $directives[strtolower($part)] = '';
            } else {
                $name              = strtolower(substr($part, 0, $spacePos));
                $directives[$name] = substr($part, $spacePos + 1);
            }
        }

        return $directives;
    }
}
