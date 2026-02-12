<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Normalizer from ext-intl, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Uri;

use Normalizer;
use Override;
use Zappzarapp\Security\Sanitization\Exception\UnsafeUriException;
use Zappzarapp\Security\Sanitization\InputFilter;

/**
 * URI sanitizer with XSS prevention and optional SSRF protection
 *
 * Blocks dangerous URI schemes like javascript: and vbscript:
 * When configured for server-side use, also blocks private network addresses.
 */
final readonly class UriSanitizer implements InputFilter
{
    public function __construct(
        private UriSanitizerConfig $config = new UriSanitizerConfig(),
        private PrivateNetworkValidator $networkValidator = new PrivateNetworkValidator(),
    ) {
    }

    /**
     * Validate a URI
     *
     * @param string $uri The URI to validate
     *
     * @throws UnsafeUriException If URI is unsafe
     */
    public function validate(string $uri): void
    {
        $uri = trim($uri);

        if ($uri === '') {
            return;
        }

        // Normalize for detection (handle encoded variants)
        $normalized = $this->normalizeForDetection($uri);

        // Parse the URI
        $scheme = $this->extractScheme($normalized);

        // Handle relative URIs
        if ($scheme === null) {
            if (!$this->config->allowRelative) {
                throw UnsafeUriException::invalidUri($uri);
            }

            return;
        }

        $scheme = strtolower($scheme);

        // Check blocked schemes
        if (in_array($scheme, $this->config->blockedSchemes, true)) {
            throw UnsafeUriException::blockedScheme($scheme);
        }

        // Check allowed schemes
        /** @psalm-suppress RedundantCondition - blockedSchemes and allowedSchemes are independent checks */
        if ($this->config->allowedSchemes !== [] && !in_array($scheme, $this->config->allowedSchemes, true)) {
            throw UnsafeUriException::blockedScheme($scheme);
        }

        // Check host restrictions
        $this->validateHost($uri);
    }

    /**
     * Sanitize a URI, returning empty string for unsafe URIs
     *
     * @psalm-taint-escape html
     */
    #[Override]
    public function sanitize(string $input): string
    {
        try {
            $this->validate($input);

            return $input;
        } catch (UnsafeUriException) {
            return '';
        }
    }

    /**
     * Check if URI is safe
     */
    #[Override]
    public function isSafe(string $input): bool
    {
        try {
            $this->validate($input);

            return true;
        } catch (UnsafeUriException) {
            return false;
        }
    }

    /**
     * Normalize URI for scheme detection
     *
     * Handles various encoding tricks used in XSS attacks.
     */
    private function normalizeForDetection(string $uri): string
    {
        $normalized = $uri;

        // Remove leading/trailing whitespace
        $normalized = trim($normalized);

        // Unicode normalization (NFC) to prevent homograph attacks
        if (function_exists('normalizer_normalize')) {
            $normalized = Normalizer::normalize($normalized, Normalizer::FORM_C) ?: $normalized;
        }

        // Decode HTML entities
        $normalized = html_entity_decode((string) $normalized, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // URL decode
        $normalized = rawurldecode($normalized);

        // Remove null bytes
        $normalized = str_replace("\0", '', $normalized);

        // Remove control characters
        $normalized = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $normalized) ?? $normalized;

        // Collapse whitespace in scheme area
        /** @noinspection PhpUnnecessaryLocalVariableInspection Explicit variable improves readability */
        $normalized = preg_replace('/^([a-zA-Z][a-zA-Z0-9+.-]*)\s*:/i', '$1:', $normalized) ?? $normalized;

        return $normalized;
    }

    /**
     * Extract scheme from URI
     */
    private function extractScheme(string $uri): ?string
    {
        // Match scheme pattern: letters, digits, plus, period, or hyphen
        if (preg_match('/^([a-zA-Z][a-zA-Z0-9+.-]*):/', $uri, $matches) === 1) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Validate host restrictions
     *
     * @throws UnsafeUriException If host is blocked
     */
    private function validateHost(string $uri): void
    {
        $parsed = parse_url($uri);
        if ($parsed === false || !isset($parsed['host'])) {
            return;
        }

        $host = strtolower($parsed['host']);

        // SSRF protection: check for private/reserved networks
        if ($this->config->blockPrivateNetworks && $this->networkValidator->isPrivateOrReserved($host)) {
            throw UnsafeUriException::blockedHost($host);
        }

        // IDN homograph attack protection
        if ($this->config->blockMixedScriptIdn) {
            $this->validateIdnHost($host);
        }

        // Check blocked hosts
        foreach ($this->config->blockedHosts as $blocked) {
            if ($host === strtolower($blocked) || str_ends_with($host, '.' . strtolower($blocked))) {
                throw UnsafeUriException::blockedHost($host);
            }
        }

        // Check allowed hosts (if list is non-empty)
        if ($this->config->allowedHosts !== []) {
            $allowed = array_any($this->config->allowedHosts, fn(string $allowedHost): bool => $host === strtolower($allowedHost) || str_ends_with($host, '.' . strtolower($allowedHost)));
            if (!$allowed) {
                throw UnsafeUriException::blockedHost($host);
            }
        }
    }

    /**
     * Validate IDN host for homograph attacks
     *
     * Detects mixed-script IDN domains that could be used for phishing.
     * For example: "аpple.com" (Cyrillic 'а') vs "apple.com" (Latin 'a')
     *
     * @throws UnsafeUriException If host contains suspicious mixed scripts
     */
    private function validateIdnHost(string $host): void
    {
        // Skip if not an internationalized domain
        if (!preg_match('/[^\x00-\x7F]/', $host)) {
            return;
        }

        // Convert to ASCII (Punycode) for comparison
        if (function_exists('idn_to_ascii')) {
            $ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);

            if ($ascii === false) {
                throw UnsafeUriException::blockedHost($host);
            }

            // Check for mixed scripts in the original Unicode host
            $this->detectMixedScripts($host);
        }
    }

    /**
     * Detect mixed Unicode scripts in a hostname
     *
     * Mixed-script domains (e.g., Latin + Cyrillic) are often used in homograph attacks.
     *
     * @throws UnsafeUriException If mixed scripts detected
     */
    private function detectMixedScripts(string $host): void
    {
        // Remove common separators
        $labels = explode('.', $host);

        foreach ($labels as $label) {
            if ($label === '') {
                continue;
            }

            $hasLatin    = false;
            $hasCyrillic = false;
            $hasGreek    = false;

            // Check each character's script
            if (preg_match('/\p{Latin}/u', $label)) {
                $hasLatin = true;
            }

            if (preg_match('/\p{Cyrillic}/u', $label)) {
                $hasCyrillic = true;
            }

            if (preg_match('/\p{Greek}/u', $label)) {
                $hasGreek = true;
            }

            // Detect dangerous combinations
            $scriptCount = ($hasLatin ? 1 : 0) + ($hasCyrillic ? 1 : 0) + ($hasGreek ? 1 : 0);

            /** @noinspection PhpConditionAlreadyCheckedInspection IDE cannot infer preg_match sets flags */
            if ($scriptCount > 1) {
                throw UnsafeUriException::blockedHost($host);
            }
        }
    }
}
