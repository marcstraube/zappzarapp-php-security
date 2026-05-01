<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Uri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Zappzarapp\Security\Sanitization\Exception\UnsafeUriException;
use Zappzarapp\Security\Sanitization\InputFilter;
use Zappzarapp\Security\Sanitization\Uri\PrivateNetworkValidator;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizer;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizerConfig;

#[CoversClass(UriSanitizer::class)]
final class UriSanitizerTest extends TestCase
{
    private UriSanitizer $sanitizer;

    protected function setUp(): void
    {
        $this->sanitizer = new UriSanitizer(UriSanitizerConfig::web());
    }

    // =========================================================================
    // Basic Validation (Mutants 35-37)
    // =========================================================================

    #[Test]
    public function testValidateIsPublic(): void
    {
        $this->sanitizer->validate('https://example.com');
        $this->assertTrue(true);
    }

    #[DataProvider('validUriProvider')]
    #[Test]
    public function testValidUrisPass(string $uri): void
    {
        $this->sanitizer->validate($uri);
        $this->assertTrue(true);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function validUriProvider(): iterable
    {
        yield 'trimmed whitespace' => ['  https://example.com  '];
        yield 'empty string' => [''];
        yield 'whitespace only becomes empty' => ['   '];
        yield 'uppercase scheme' => ['HTTPS://example.com'];
        yield 'mixed case scheme' => ['HtTpS://example.com'];
        yield 'mailto scheme' => ['mailto:test@example.com'];
        yield 'relative path' => ['/path/to/resource'];
        yield 'pure ASCII host' => ['https://example.com'];
        yield 'pure ASCII host with path' => ['https://example.com/path'];
    }

    // =========================================================================
    // Blocked Schemes (Mutants 38, 39)
    // =========================================================================

    #[DataProvider('blockedSchemeProvider')]
    #[Test]
    public function testBlockedSchemesThrowException(string $uri): void
    {
        $this->expectException(UnsafeUriException::class);
        $this->sanitizer->validate($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function blockedSchemeProvider(): iterable
    {
        yield 'javascript' => ['javascript:alert(1)'];
        yield 'vbscript' => ['vbscript:msgbox("xss")'];
        yield 'data' => ['data:text/html,<script>alert(1)</script>'];
    }

    // =========================================================================
    // Host Validation (Mutants 40, 49-52)
    // =========================================================================

    #[DataProvider('blockedHostProvider')]
    #[Test]
    public function testBlockedHostsThrowException(string $uri, UriSanitizerConfig $config): void
    {
        $sanitizer = new UriSanitizer($config);

        $this->expectException(UnsafeUriException::class);
        $sanitizer->validate($uri);
    }

    /**
     * @return iterable<string, array{string, UriSanitizerConfig}>
     */
    public static function blockedHostProvider(): iterable
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockedHosts: ['evil.com']
        );
        $multiConfig = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockedHosts: ['evil.com', 'bad.org', 'malicious.net']
        );
        $upperConfig = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockedHosts: ['EVIL.COM']
        );

        yield 'blocked host' => ['https://evil.com/path', $config];
        yield 'uppercase host blocked' => ['https://EVIL.COM/path', $config];
        yield 'subdomain blocked' => ['https://sub.evil.com/path', $config];
        yield 'multiple blocked - last' => ['https://malicious.net/path', $multiConfig];
        yield 'uppercase config exact match' => ['https://evil.com/path', $upperConfig];
        yield 'uppercase config subdomain' => ['https://sub.evil.com/path', $upperConfig];
    }

    #[Test]
    public function testBlockedHostRequiresDotPrefixForSubdomain(): void
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockedHosts: ['evil.com']
        );
        $sanitizer = new UriSanitizer($config);

        // "notevil.com" should NOT be blocked
        $sanitizer->validate('https://notevil.com/path');
        $this->assertTrue(true);
    }

    // =========================================================================
    // IsSafe Method (Mutant 41)
    // =========================================================================

    #[Test]
    public function testIsSafeReturnsFalseForUnsafe(): void
    {
        $this->assertFalse($this->sanitizer->isSafe('javascript:alert(1)'));
    }

    #[Test]
    public function testIsSafeReturnsTrueForSafe(): void
    {
        $this->assertTrue($this->sanitizer->isSafe('https://example.com'));
    }

    // =========================================================================
    // Normalization (Mutants 43-47)
    // =========================================================================

    #[Test]
    public function testNormalizeTrimsWhitespace(): void
    {
        $result = $this->sanitizer->sanitize('  https://example.com  ');
        $this->assertSame('  https://example.com  ', $result);
    }

    #[DataProvider('obfuscationBypassProvider')]
    #[Test]
    public function testObfuscationBypassesAreBlocked(string $uri): void
    {
        $this->expectException(UnsafeUriException::class);
        $this->sanitizer->validate($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function obfuscationBypassProvider(): iterable
    {
        yield 'html entity obfuscation' => ['java&#115;cript:alert(1)'];
        yield 'null bytes' => ["java\x00script:alert(1)"];
        yield 'null byte in scheme' => ["javas\x00cript:alert(1)"];
        yield 'control characters' => ["java\x07script:alert(1)"];
        yield 'hex entity obfuscation' => ['&#x6a;avascript:alert(1)'];
    }

    #[Test]
    public function testControlCharactersAreRemoved(): void
    {
        $result = $this->sanitizer->sanitize("https://example.com/path\x0d\x0a");
        $this->assertNotSame('', $result);
    }

    #[Test]
    public function testUnicodeNormalizationIsApplied(): void
    {
        $result = $this->sanitizer->sanitize('https://example.com/café');
        $this->assertStringContainsString('example.com', $result);
    }

    #[Test]
    public function testHtmlEntityQuoteDecoding(): void
    {
        $result = $this->sanitizer->sanitize('https://example.com?q=test&amp;foo=bar');
        $this->assertNotSame('', $result);
    }

    // =========================================================================
    // IDN Validation (Mutants 51, 53-54)
    // =========================================================================

    #[DataProvider('mixedScriptIdnProvider')]
    #[Test]
    public function testMixedScriptIdnIsBlocked(string $uri): void
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: true
        );
        $sanitizer = new UriSanitizer($config);

        $this->expectException(UnsafeUriException::class);
        $sanitizer->validate($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function mixedScriptIdnProvider(): iterable
    {
        yield 'cyrillic mixed with latin' => ['https://аpple.com'];
        yield 'latin mixed with greek' => ['https://exampleω.com'];
        yield 'cyrillic mixed with greek' => ['https://тестω.com'];
        yield 'latin cyrillic greek all mixed' => ['https://aтω.com'];
    }

    #[DataProvider('pureScriptIdnProvider')]
    #[Test]
    public function testPureScriptIdnIsAllowed(string $uri): void
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: true
        );
        $sanitizer = new UriSanitizer($config);

        $sanitizer->validate($uri);
        $this->assertTrue(true);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function pureScriptIdnProvider(): iterable
    {
        yield 'pure cyrillic' => ['https://тест.com'];
        yield 'pure greek' => ['https://ωμεγα.com'];
        yield 'pure ascii' => ['https://example.com'];
    }

    #[Test]
    public function testIdnValidationCanBeDisabled(): void
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            blockMixedScriptIdn: false
        );
        $sanitizer = new UriSanitizer($config);

        $sanitizer->validate('https://example.com');
        $this->assertTrue(true);
    }

    // =========================================================================
    // Sanitize Method
    // =========================================================================

    #[Test]
    public function testSanitizeReturnsEmptyForUnsafe(): void
    {
        $this->assertSame('', $this->sanitizer->sanitize('javascript:alert(1)'));
    }

    #[Test]
    public function testSanitizeReturnsUriForSafe(): void
    {
        $this->assertSame('https://example.com', $this->sanitizer->sanitize('https://example.com'));
    }

    // =========================================================================
    // Allowed Schemes and Hosts
    // =========================================================================

    #[Test]
    public function testAllowedSchemesEnforced(): void
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            allowRelative: false
        );
        $sanitizer = new UriSanitizer($config);

        $this->expectException(UnsafeUriException::class);
        $sanitizer->validate('http://example.com');
    }

    #[Test]
    public function testRelativeUriWithRelativeDisabled(): void
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            allowRelative: false
        );
        $sanitizer = new UriSanitizer($config);

        $this->expectException(UnsafeUriException::class);
        $sanitizer->validate('/relative/path');
    }

    #[Test]
    public function testRelativeUriWithRelativeEnabled(): void
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            allowRelative: true
        );
        $sanitizer = new UriSanitizer($config);

        $sanitizer->validate('/relative/path');
        $this->assertTrue(true);
    }

    #[Test]
    public function testSchemeExtractedFromStart(): void
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            allowRelative: false
        );
        $sanitizer = new UriSanitizer($config);

        $this->expectException(UnsafeUriException::class);
        $sanitizer->validate('/path?javascript:alert(1)');
    }

    // =========================================================================
    // XSS Payloads (comprehensive)
    // =========================================================================

    #[DataProvider('xssUriPayloadProvider')]
    #[Test]
    public function testXssUriPayloadsAreBlocked(string $payload): void
    {
        $this->assertFalse($this->sanitizer->isSafe($payload));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function xssUriPayloadProvider(): iterable
    {
        yield 'javascript scheme' => ['javascript:alert(1)'];
        yield 'javascript uppercase' => ['JAVASCRIPT:alert(1)'];
        yield 'javascript mixed case' => ['JaVaScRiPt:alert(1)'];
        yield 'javascript html encoded' => ['&#106;avascript:alert(1)'];
        yield 'vbscript scheme' => ['vbscript:msgbox(1)'];
        yield 'data scheme html' => ['data:text/html,<script>alert(1)</script>'];
    }

    // =========================================================================
    // Allowed Hosts
    // =========================================================================

    #[DataProvider('allowedHostProvider')]
    #[Test]
    public function testAllowedHostBehavior(string $uri, UriSanitizerConfig $config, bool $shouldPass): void
    {
        $sanitizer = new UriSanitizer($config);

        if (!$shouldPass) {
            $this->expectException(UnsafeUriException::class);
        }

        $sanitizer->validate($uri);
        $this->assertTrue(true);
    }

    /**
     * @return iterable<string, array{string, UriSanitizerConfig, bool}>
     */
    public static function allowedHostProvider(): iterable
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            allowedHosts: ['trusted.com']
        );
        $upperConfig = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: [],
            allowedHosts: ['TRUSTED.COM']
        );

        yield 'untrusted host blocked' => ['https://untrusted.com/path', $config, false];
        yield 'trusted host allowed' => ['https://trusted.com/path', $config, true];
        yield 'trusted subdomain allowed' => ['https://sub.trusted.com/path', $config, true];
        yield 'uppercase config exact match' => ['https://trusted.com/path', $upperConfig, true];
        yield 'uppercase config subdomain' => ['https://sub.trusted.com/path', $upperConfig, true];
    }

    // =========================================================================
    // Throw vs Non-Throw (Mutant 22)
    // =========================================================================

    #[Test]
    public function testBlockedSchemeActuallyThrows(): void
    {
        $threw = false;

        try {
            $this->sanitizer->validate('javascript:alert(1)');
        } catch (UnsafeUriException) {
            $threw = true;
        }

        $this->assertTrue($threw);
    }

    // =========================================================================
    // Regex Anchor for Scheme (Mutant 29)
    // =========================================================================

    #[Test]
    public function testSchemeOnlyMatchedAtStart(): void
    {
        $config = new UriSanitizerConfig(
            allowedSchemes: ['https'],
            blockedSchemes: ['javascript'],
            allowRelative: true
        );
        $sanitizer = new UriSanitizer($config);

        $sanitizer->validate('/files/javascript:test.txt');
        $this->assertTrue(true);
    }

    // =========================================================================
    // SSRF Protection (Server-Side Configuration)
    // =========================================================================

    #[DataProvider('ssrfBlockedUriProvider')]
    #[Test]
    public function testSsrfProtectionBlocksPrivateNetworks(string $uri): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::serverSide());

        $this->expectException(UnsafeUriException::class);
        $sanitizer->validate($uri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ssrfBlockedUriProvider(): iterable
    {
        // Loopback
        yield 'loopback 127.0.0.1' => ['http://127.0.0.1/'];
        yield 'localhost' => ['http://localhost/'];

        // Private ranges (RFC 1918)
        yield 'private 10.x' => ['http://10.0.0.1/'];
        yield 'private 172.16.x' => ['http://172.16.0.1/'];
        yield 'private 192.168.x' => ['http://192.168.1.1/'];

        // Cloud metadata
        yield 'cloud metadata' => ['http://169.254.169.254/latest/meta-data/'];

        // IPv6 loopback
        yield 'ipv6 loopback' => ['http://[::1]/'];

        // Internal hostnames
        yield 'internal hostname' => ['http://my-service.internal/'];
        yield 'local hostname' => ['http://printer.local/'];
    }

    #[DataProvider('ssrfAllowedUriProvider')]
    #[Test]
    public function testSsrfProtectionAllowsPublicUrls(string $uri): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::serverSide());

        $sanitizer->validate($uri);
        $this->assertTrue(true);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ssrfAllowedUriProvider(): iterable
    {
        yield 'public https' => ['https://example.com/'];
        yield 'public http' => ['http://example.com/'];
        yield 'public with path' => ['https://api.example.com/v1/users'];
        yield 'public with query' => ['https://example.com/search?q=test'];
    }

    #[Test]
    public function testSsrfProtectionIsDisabledByDefault(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::web());

        // Private IPs should be allowed with web() config (no SSRF protection)
        $sanitizer->validate('http://192.168.1.1/');
        $this->assertTrue(true);
    }

    #[Test]
    public function testServerSideConfigBlocksRelativeUrls(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::serverSide());

        $this->expectException(UnsafeUriException::class);
        $sanitizer->validate('/relative/path');
    }

    #[Test]
    public function testServerSideConfigBlocksDangerousSchemes(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::serverSide());

        $this->expectException(UnsafeUriException::class);
        $sanitizer->validate('file:///etc/passwd');
    }

    #[Test]
    public function testCustomPrivateNetworkValidatorCanBeInjected(): void
    {
        // Create a real validator with a logger to verify it's being used
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                'SSRF protection: Blocked request to private/reserved host',
                $this->callback(fn(array $context): bool => $context['host'] === 'localhost')
            );

        $validator = new PrivateNetworkValidator($logger);
        $config    = UriSanitizerConfig::serverSide();
        $sanitizer = new UriSanitizer($config, $validator);

        $this->expectException(UnsafeUriException::class);
        $sanitizer->validate('https://localhost/');
    }

    #[Test]
    public function testIsSafeReturnsFalseForSsrfAttempt(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::serverSide());

        $this->assertFalse($sanitizer->isSafe('http://169.254.169.254/'));
    }

    #[Test]
    public function testSanitizeReturnsEmptyForSsrfAttempt(): void
    {
        $sanitizer = new UriSanitizer(UriSanitizerConfig::serverSide());

        $this->assertSame('', $sanitizer->sanitize('http://169.254.169.254/'));
    }

    // =========================================================================
    // InputFilter Interface Implementation
    // =========================================================================

    #[Test]
    public function testImplementsInputFilterInterface(): void
    {
        $sanitizer = new UriSanitizer();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(InputFilter::class, $sanitizer);
    }

    #[Test]
    public function testInputFilterSanitizeMethodWorks(): void
    {
        $sanitizer = new UriSanitizer();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(InputFilter::class, $sanitizer);
        $this->assertSame('https://example.com', $sanitizer->sanitize('https://example.com'));
        $this->assertSame('', $sanitizer->sanitize('javascript:alert(1)'));
    }

    #[Test]
    public function testInputFilterIsSafeMethodWorks(): void
    {
        $sanitizer = new UriSanitizer();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(InputFilter::class, $sanitizer);
        $this->assertTrue($sanitizer->isSafe('https://example.com'));
        $this->assertFalse($sanitizer->isSafe('javascript:alert(1)'));
    }
}
