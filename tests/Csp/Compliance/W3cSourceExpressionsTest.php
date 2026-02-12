<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Compliance;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;
use Zappzarapp\Security\Csp\SecurityPolicy;

/**
 * W3C CSP Source Expression Compliance Tests
 *
 * Tests that CSP source expressions are correctly formatted according to spec.
 *
 * @see https://www.w3.org/TR/CSP3/#framework-directive-source-list
 */
final class W3cSourceExpressionsTest extends TestCase
{
    private const string NONCE = 'dGVzdC1ub25jZS12YWx1ZQ==';

    // =========================================================================
    // Keyword Source Tests (W3C CSP3 Section 2.3.1)
    // =========================================================================

    #[DataProvider('keywordSourceProvider')]
    public function testKeywordSourcesAreSingleQuoted(string $keyword, string $directive, string $value): void
    {
        // Use LENIENT policy for unsafe keywords to avoid warnings
        $policy     = SecurityPolicy::LENIENT;
        $directives = match ($directive) {
            'script-src' => new CspDirectives(scriptSrc: $value, securityPolicy: $policy),
            'style-src'  => new CspDirectives(styleSrc: $value, securityPolicy: $policy),
            'img-src'    => new CspDirectives(resources: new ResourceDirectives(img: $value)),
            default      => new CspDirectives(defaultSrc: $value),
        };

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("'$keyword'", $header);
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function keywordSourceProvider(): array
    {
        return [
            'self'           => ['self', 'default-src', "'self'"],
            'none'           => ['none', 'img-src', "'none'"],
            'unsafe-inline'  => ['unsafe-inline', 'script-src', "'unsafe-inline'"],
            'unsafe-eval'    => ['unsafe-eval', 'script-src', "'unsafe-eval'"],
            'strict-dynamic' => ['strict-dynamic', 'script-src', "'strict-dynamic'"],
        ];
    }

    public function testSelfKeywordFormat(): void
    {
        $directives = new CspDirectives(defaultSrc: "'self'");

        $header = $directives->toHeaderValue(self::NONCE);

        // 'self' must be quoted
        $this->assertStringContainsString("'self'", $header);
        $this->assertStringNotContainsString('self ', $header); // unquoted
    }

    public function testNoneKeywordFormat(): void
    {
        $resources  = new ResourceDirectives(img: "'none'");
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        // 'none' must be quoted
        $this->assertStringContainsString("'none'", $header);
    }

    // =========================================================================
    // Nonce Source Tests (W3C CSP3 Section 2.3.2)
    // =========================================================================

    public function testNonceSourceFormat(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        // Nonce format: 'nonce-<base64>'
        $this->assertMatchesRegularExpression("/'nonce-[A-Za-z0-9+\\/=]+'/", $header);
    }

    public function testNonceIsBase64Encoded(): void
    {
        $nonce      = 'dGVzdC1ub25jZQ=='; // base64("test-nonce")
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue($nonce);

        $this->assertStringContainsString("'nonce-$nonce'", $header);
    }

    public function testNonceInScriptSrc(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertMatchesRegularExpression("/script-src[^;]*'nonce-" . self::NONCE . "'/", $header);
    }

    public function testNonceInStyleSrc(): void
    {
        $directives = CspDirectives::strict();

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertMatchesRegularExpression("/style-src[^;]*'nonce-" . self::NONCE . "'/", $header);
    }

    // =========================================================================
    // Scheme Source Tests (W3C CSP3 Section 2.3.3)
    // =========================================================================

    #[DataProvider('schemeSourceProvider')]
    public function testSchemeSourceFormat(string $scheme): void
    {
        $directives = new CspDirectives(defaultSrc: "$scheme:");

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("$scheme:", $header);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function schemeSourceProvider(): array
    {
        return [
            'https'  => ['https'],
            'data'   => ['data'],
            'blob'   => ['blob'],
            'wss'    => ['wss'],
        ];
    }

    // =========================================================================
    // Host Source Tests (W3C CSP3 Section 2.3.4)
    // =========================================================================

    public function testHostSourceWithScheme(): void
    {
        $directives = new CspDirectives(defaultSrc: "https://example.com");

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('https://example.com', $header);
    }

    public function testHostSourceWithWildcardSubdomain(): void
    {
        $directives = new CspDirectives(defaultSrc: "*.example.com");

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('*.example.com', $header);
    }

    public function testHostSourceWithPort(): void
    {
        $directives = new CspDirectives(defaultSrc: "https://example.com:443");

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('https://example.com:443', $header);
    }

    public function testHostSourceWithPath(): void
    {
        $directives = new CspDirectives(defaultSrc: "https://example.com/scripts/");

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString('https://example.com/scripts/', $header);
    }

    // =========================================================================
    // Multiple Sources Tests
    // =========================================================================

    public function testMultipleSourcesSeparatedBySpace(): void
    {
        $directives = new CspDirectives(
            defaultSrc: "'self' https://cdn.example.com https://api.example.com"
        );

        $header = $directives->toHeaderValue(self::NONCE);

        // Multiple sources must be space-separated
        $this->assertStringContainsString("'self' https://cdn.example.com https://api.example.com", $header);
    }

    public function testCombinedKeywordsAndHosts(): void
    {
        $resources = new ResourceDirectives(
            img: "'self' data: https://images.example.com"
        );
        $directives = new CspDirectives(resources: $resources);

        $header = $directives->toHeaderValue(self::NONCE);

        $this->assertStringContainsString("img-src 'self' data: https://images.example.com", $header);
    }
}
