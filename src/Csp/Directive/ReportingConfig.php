<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Directive;

use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;
use Zappzarapp\Security\Csp\Validation\ValidatesDirectiveValues;

/**
 * CSP Reporting and Security Upgrade Configuration
 *
 * Controls HTTP upgrade behavior and CSP violation reporting.
 * Immutable value object with fluent API.
 *
 * @psalm-api
 */
final readonly class ReportingConfig
{
    use ValidatesDirectiveValues;

    /**
     * @param bool $upgradeInsecure Upgrade HTTP requests to HTTPS (upgrade-insecure-requests)
     * @param string|null $uri URI for CSP violation reports (report-uri directive, deprecated in CSP Level 3)
     * @param string|null $endpoint Reporting API endpoint name (report-to, replaces report-uri)
     * @throws InvalidDirectiveValueException If values contain injection characters
     * @SuppressWarnings(BooleanArgumentFlag) VO constructor property, not behavior switch
     */
    public function __construct(
        public bool $upgradeInsecure = true,
        public ?string $uri = null,
        public ?string $endpoint = null,
    ) {
        $this->validate();
    }

    /**
     * Create new instance with modified upgrade-insecure-requests
     *
     * @psalm-api
     */
    public function withUpgradeInsecure(bool $enabled): self
    {
        return $this->cloneWith(upgradeInsecure: $enabled);
    }

    /**
     * Create new instance with report-uri
     *
     * @psalm-api
     */
    public function withUri(string $uri): self
    {
        return $this->cloneWith(uri: $uri);
    }

    /**
     * Create new instance with report-to endpoint
     *
     * @psalm-api
     */
    public function withEndpoint(string $endpoint): self
    {
        return $this->cloneWith(endpoint: $endpoint);
    }

    /**
     * Create a clone with specified property overrides
     */
    private function cloneWith(
        ?bool $upgradeInsecure = null,
        ?string $uri = null,
        ?string $endpoint = null,
    ): self {
        return new self(
            upgradeInsecure: $upgradeInsecure ?? $this->upgradeInsecure,
            uri: $uri ?? $this->uri,
            endpoint: $endpoint ?? $this->endpoint,
        );
    }

    /**
     * Validate configuration for injection attacks and security requirements
     *
     * @throws InvalidDirectiveValueException If values contain injection characters or violate security requirements
     */
    private function validate(): void
    {
        if ($this->uri !== null) {
            $this->validateDirectiveValue('report-uri', $this->uri);
            $this->validateReportUriScheme($this->uri);
        }

        if ($this->endpoint !== null) {
            $this->validateDirectiveValue('report-to', $this->endpoint);
        }
    }

    /**
     * Validate that report-uri uses HTTPS
     *
     * CSP violation reports may contain sensitive information about the page
     * structure and blocked resources. Transmitting over HTTP exposes this data.
     *
     * @throws InvalidDirectiveValueException If report-uri uses insecure HTTP scheme
     */
    private function validateReportUriScheme(string $uri): void
    {
        $scheme = parse_url($uri, PHP_URL_SCHEME);

        if (is_string($scheme) && strtolower($scheme) === 'http') {
            throw InvalidDirectiveValueException::insecureReportUri($uri);
        }
    }

}
