<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\PropertyBased;

use Eris\Generators;
use Eris\TestTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Builder\SecurityHeadersBuilder;
use Zappzarapp\Security\Headers\Hsts\HstsConfig;
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionsPolicy;
use Zappzarapp\Security\Headers\SecurityHeaders;

/**
 * Property-based tests for security headers injection prevention
 *
 * These tests verify that security header values are validated
 * to prevent HTTP header injection attacks.
 */
#[CoversClass(SecurityHeaders::class)]
#[CoversClass(SecurityHeadersBuilder::class)]
#[CoversClass(HstsConfig::class)]
#[CoversClass(PermissionsPolicy::class)]
final class SecurityHeadersPropertyTest extends TestCase
{
    use TestTrait;

    /**
     * Property: Generated security headers are always single-line
     */
    public function testGeneratedHeadersAreSingleLine(): void
    {
        $headers = SecurityHeaders::strict();
        $builder = new SecurityHeadersBuilder($headers);
        $result  = $builder->build();

        foreach ($result as $name => $value) {
            $this->assertStringNotContainsString("\r", $value, "Header {$name} contains CR");
            $this->assertStringNotContainsString("\n", $value, "Header {$name} contains LF");
            $this->assertStringNotContainsString("\x00", $value, "Header {$name} contains null");
        }
    }

    /**
     * Property: SecurityHeaders output is consistent and safe
     */
    public function testSecurityHeadersOutputIsSafe(): void
    {
        $configs = [
            SecurityHeaders::strict(),
            SecurityHeaders::moderate(),
            SecurityHeaders::legacy(),
            SecurityHeaders::development(),
            SecurityHeaders::api(),
        ];

        foreach ($configs as $config) {
            $builder = new SecurityHeadersBuilder($config);
            $headers = $builder->build();

            foreach ($headers as $name => $value) {
                // Name validation
                $this->assertMatchesRegularExpression(
                    '/^[A-Za-z][A-Za-z0-9-]*$/',
                    $name,
                    "Invalid header name format: {$name}"
                );

                // Value validation - no control characters
                $this->assertDoesNotMatchRegularExpression(
                    '/[\x00-\x1F]/',
                    $value,
                    "Header {$name} contains control characters"
                );
            }
        }
    }

    /**
     * Property: Random HSTS max-age values within bounds produce valid headers
     */
    public function testRandomHstsMaxAgeProducesValidHeaders(): void
    {
        $this->forAll(
            Generators::choose(0, 63072000) // 0 to 2 years
        )->then(function (int $maxAge): void {
            // Preload requires >= 31536000 (1 year)
            $preload           = $maxAge >= 31536000;
            $includeSubDomains = $preload; // preload requires includeSubDomains

            $hsts = new HstsConfig(
                maxAge: $maxAge,
                includeSubDomains: $includeSubDomains,
                preload: $preload
            );

            $headers = SecurityHeaders::development()->withHsts($hsts);
            $builder = new SecurityHeadersBuilder($headers);
            $result  = $builder->build();

            $this->assertArrayHasKey('Strict-Transport-Security', $result);
            $this->assertStringContainsString("max-age={$maxAge}", $result['Strict-Transport-Security']);

            // Verify no injection artifacts
            $this->assertStringNotContainsString("\r", $result['Strict-Transport-Security']);
            $this->assertStringNotContainsString("\n", $result['Strict-Transport-Security']);
        });
    }

    /**
     * Property: Header builder produces consistent output
     */
    public function testHeaderBuilderConsistency(): void
    {
        $headers = SecurityHeaders::strict();
        $builder = new SecurityHeadersBuilder($headers);

        // Multiple calls should produce identical output
        $headers1 = $builder->build();
        $headers2 = $builder->build();

        $this->assertSame($headers1, $headers2, 'Header builder should be deterministic');
    }

    /**
     * Property: All enum-based headers are structurally safe
     *
     * Headers using enums (COOP, COEP, CORP, X-Frame-Options, Referrer-Policy)
     * are inherently safe because they only allow predefined values.
     */
    public function testEnumBasedHeadersAreSafe(): void
    {
        // Use strict which includes all enum-based headers
        $headers = SecurityHeaders::strict();
        $builder = new SecurityHeadersBuilder($headers);
        $result  = $builder->build();

        foreach ($result as $name => $value) {
            // Control characters should never appear (injection artifacts)
            // Note: Semicolons are legitimate in HSTS (max-age=...; includeSubDomains)
            $this->assertDoesNotMatchRegularExpression(
                '/[\r\n\x00]/',
                $value,
                "Header {$name} contains control characters"
            );
        }
    }

    /**
     * Property: X-Content-Type-Options is always "nosniff"
     *
     * This header has only one valid value, preventing any injection.
     */
    public function testXContentTypeOptionsIsAlwaysNosniff(): void
    {
        $headers = new SecurityHeaders(xContentTypeOptions: true);
        $builder = new SecurityHeadersBuilder($headers);
        $result  = $builder->build();

        $this->assertArrayHasKey('X-Content-Type-Options', $result);
        $this->assertSame('nosniff', $result['X-Content-Type-Options']);
    }

    /**
     * Property: Empty SecurityHeaders produces minimal output
     */
    public function testEmptySecurityHeadersProducesMinimalOutput(): void
    {
        $headers = new SecurityHeaders(
            xContentTypeOptions: false,
            xXssProtection: false
        );
        $builder = new SecurityHeadersBuilder($headers);
        $result  = $builder->build();

        $this->assertSame([], $result);
    }

    /**
     * Property: HSTS with preload requires minimum max-age
     */
    public function testHstsPreloadRequiresMinimumMaxAge(): void
    {
        // Valid: preload with >= 1 year
        $validHsts = new HstsConfig(
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        );

        $headers = SecurityHeaders::development()->withHsts($validHsts);
        $builder = new SecurityHeadersBuilder($headers);
        $result  = $builder->build();

        $this->assertStringContainsString('preload', $result['Strict-Transport-Security']);
        $this->assertStringContainsString('includeSubDomains', $result['Strict-Transport-Security']);
    }

    /**
     * Property: All factory configurations produce valid headers
     */
    public function testFactoryConfigurationsProduceValidHeaders(): void
    {
        $factories = [
            'strict'      => SecurityHeaders::strict(),
            'moderate'    => SecurityHeaders::moderate(),
            'legacy'      => SecurityHeaders::legacy(),
            'development' => SecurityHeaders::development(),
            'api'         => SecurityHeaders::api(),
        ];

        foreach ($factories as $name => $config) {
            $builder = new SecurityHeadersBuilder($config);
            $result  = $builder->build();

            foreach ($result as $headerName => $value) {
                // All header values must be safe
                $this->assertDoesNotMatchRegularExpression(
                    '/[\x00-\x1F]/',
                    $value,
                    "Factory '{$name}' header {$headerName} contains control characters"
                );

                // Header values must be strings (can be "0" for X-XSS-Protection)
                $this->assertIsString($value, "Factory '{$name}' header {$headerName} is not a string");
            }
        }
    }

    /**
     * Property: Permissions-Policy produces valid header values
     */
    public function testPermissionsPolicyProducesValidHeaders(): void
    {
        $policy = PermissionsPolicy::strict();
        $value  = $policy->headerValue();

        // No control characters
        $this->assertDoesNotMatchRegularExpression(
            '/[\x00-\x1F]/',
            $value,
            'Permissions-Policy contains control characters'
        );

        // No header injection patterns
        $this->assertStringNotContainsString("\r\n", $value);
    }
}
