<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Builder;

use Zappzarapp\Security\Csp\Directive\CspDirectives;

/**
 * Builds CSP header value from CspDirectives
 *
 * Extracts header building logic from CspDirectives to reduce complexity.
 * Handles nonce injection, policy-based directives, and reporting configuration.
 */
final readonly class HeaderValueBuilder
{
    public function __construct(
        private CspDirectives $directives,
        private string $nonce,
    ) {}

    /**
     * Build complete CSP header value
     */
    public function build(): string
    {
        $directiveMap = [
            'default-src'     => $this->directives->defaultSrc,
            'script-src'      => $this->buildScriptSrc(),
            'style-src'       => $this->buildStyleSrc(),
            'img-src'         => $this->directives->resources->img,
            'font-src'        => $this->directives->resources->font,
            'connect-src'     => $this->buildConnectSrc(),
            'media-src'       => $this->directives->resources->media,
            'worker-src'      => $this->directives->resources->worker,
            'child-src'       => $this->directives->resources->child,
            'frame-src'       => $this->directives->resources->frame,
            'manifest-src'    => $this->directives->resources->manifest,
            'object-src'      => "'none'",
            'frame-ancestors' => $this->directives->navigation->frameAncestors,
            'base-uri'        => $this->directives->navigation->baseUri,
            'form-action'     => $this->directives->navigation->formAction,
        ];

        $parts = [];
        foreach ($directiveMap as $directive => $value) {
            if ($value !== '') {
                $parts[] = sprintf('%s %s', $directive, $value);
            }
        }

        // Add upgrade-insecure-requests (no value)
        if ($this->directives->reporting->upgradeInsecure) {
            $parts[] = 'upgrade-insecure-requests';
        }

        // Add report-uri if set
        if ($this->directives->reporting->uri !== null) {
            $parts[] = sprintf('report-uri %s', $this->directives->reporting->uri);
        }

        // Add report-to if set
        if ($this->directives->reporting->endpoint !== null) {
            $parts[] = sprintf('report-to %s', $this->directives->reporting->endpoint);
        }

        return implode('; ', $parts);
    }

    /**
     * Build script-src directive with nonce
     */
    private function buildScriptSrc(): string
    {
        if ($this->directives->scriptSrc !== null) {
            // User provided custom script-src
            if (!str_contains($this->directives->scriptSrc, 'nonce-') && $this->nonce !== '') {
                return sprintf("'nonce-%s' %s", $this->nonce, $this->directives->scriptSrc);
            }

            return $this->directives->scriptSrc;
        }

        // Default: nonce-based with strict-dynamic
        $parts = ["'self'"];

        if ($this->nonce !== '') {
            $parts[] = sprintf("'nonce-%s'", $this->nonce);
            $parts[] = "'strict-dynamic'";
        }

        if ($this->directives->securityPolicy->allowsUnsafeEval()) {
            $parts[] = "'unsafe-eval'";
        }

        return implode(' ', $parts);
    }

    /**
     * Build style-src directive with nonce
     */
    private function buildStyleSrc(): string
    {
        if ($this->directives->styleSrc !== null) {
            // User provided custom style-src
            if (!str_contains($this->directives->styleSrc, 'nonce-') && $this->nonce !== '') {
                return sprintf("'nonce-%s' %s", $this->nonce, $this->directives->styleSrc);
            }

            return $this->directives->styleSrc;
        }

        // Default: nonce-based or unsafe-inline (when allowed by policy)
        $parts = ["'self'"];

        if ($this->directives->securityPolicy->allowsUnsafeInline()) {
            $parts[] = "'unsafe-inline'";
        } elseif ($this->nonce !== '') {
            $parts[] = sprintf("'nonce-%s'", $this->nonce);
        }

        return implode(' ', $parts);
    }

    /**
     * Build connect-src directive with optional WebSocket
     */
    private function buildConnectSrc(): string
    {
        if ($this->directives->websocketHost === null) {
            return $this->directives->resources->connect;
        }

        return sprintf(
            "%s wss://%s https://%s",
            $this->directives->resources->connect,
            $this->directives->websocketHost,
            $this->directives->websocketHost
        );
    }
}
