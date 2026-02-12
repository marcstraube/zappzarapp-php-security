<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Sanitization\Exception\UnsafeUriException;

#[CoversClass(UnsafeUriException::class)]
final class UnsafeUriExceptionTest extends TestCase
{
    // =========================================================================
    // Exception Base Class
    // =========================================================================

    public function testExtendsRuntimeException(): void
    {
        $exception = UnsafeUriException::blockedScheme('javascript');

        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    // =========================================================================
    // Factory Method: blockedScheme()
    // =========================================================================

    public function testBlockedSchemeCreatesExceptionWithCorrectMessage(): void
    {
        $exception = UnsafeUriException::blockedScheme('javascript');

        $this->assertSame('URI scheme "javascript" is not allowed', $exception->getMessage());
    }

    #[DataProvider('blockedSchemeProvider')]
    public function testBlockedSchemeWithVariousSchemes(string $scheme, string $expected): void
    {
        $exception = UnsafeUriException::blockedScheme($scheme);

        $this->assertSame($expected, $exception->getMessage());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function blockedSchemeProvider(): iterable
    {
        yield 'javascript scheme' => [
            'javascript',
            'URI scheme "javascript" is not allowed',
        ];

        yield 'vbscript scheme' => [
            'vbscript',
            'URI scheme "vbscript" is not allowed',
        ];

        yield 'data scheme' => [
            'data',
            'URI scheme "data" is not allowed',
        ];

        yield 'file scheme' => [
            'file',
            'URI scheme "file" is not allowed',
        ];

        yield 'empty scheme' => [
            '',
            'URI scheme "" is not allowed',
        ];

        yield 'uppercase scheme' => [
            'JAVASCRIPT',
            'URI scheme "JAVASCRIPT" is not allowed',
        ];

        yield 'mixed case scheme' => [
            'JaVaScRiPt',
            'URI scheme "JaVaScRiPt" is not allowed',
        ];
    }

    // =========================================================================
    // Factory Method: invalidUri()
    // =========================================================================

    public function testInvalidUriCreatesExceptionWithCorrectMessage(): void
    {
        $exception = UnsafeUriException::invalidUri('not-a-valid-uri');

        $this->assertSame('Invalid URI: not-a-valid-uri', $exception->getMessage());
    }

    #[DataProvider('invalidUriProvider')]
    public function testInvalidUriWithVariousUris(string $uri, string $expected): void
    {
        $exception = UnsafeUriException::invalidUri($uri);

        $this->assertSame($expected, $exception->getMessage());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function invalidUriProvider(): iterable
    {
        yield 'malformed uri' => [
            'http://:invalid',
            'Invalid URI: http://:invalid',
        ];

        yield 'missing scheme' => [
            '://example.com',
            'Invalid URI: ://example.com',
        ];

        yield 'special characters' => [
            'http://example.com/<script>',
            'Invalid URI: http://example.com/<script>',
        ];

        yield 'unicode uri' => [
            'http://例え.jp',
            'Invalid URI: http://例え.jp',
        ];

        yield 'empty uri' => [
            '',
            'Invalid URI: ',
        ];

        yield 'whitespace only' => [
            '   ',
            'Invalid URI:    ',
        ];
    }

    // =========================================================================
    // Factory Method: blockedHost()
    // =========================================================================

    public function testBlockedHostCreatesExceptionWithCorrectMessage(): void
    {
        $exception = UnsafeUriException::blockedHost('evil.com');

        $this->assertSame('URI host "evil.com" is not allowed', $exception->getMessage());
    }

    #[DataProvider('blockedHostProvider')]
    public function testBlockedHostWithVariousHosts(string $host, string $expected): void
    {
        $exception = UnsafeUriException::blockedHost($host);

        $this->assertSame($expected, $exception->getMessage());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function blockedHostProvider(): iterable
    {
        yield 'simple domain' => [
            'malicious.com',
            'URI host "malicious.com" is not allowed',
        ];

        yield 'subdomain' => [
            'evil.subdomain.example.com',
            'URI host "evil.subdomain.example.com" is not allowed',
        ];

        yield 'ip address' => [
            '192.168.1.1',
            'URI host "192.168.1.1" is not allowed',
        ];

        yield 'localhost' => [
            'localhost',
            'URI host "localhost" is not allowed',
        ];

        yield 'ipv6 address' => [
            '::1',
            'URI host "::1" is not allowed',
        ];

        yield 'internal ip' => [
            '10.0.0.1',
            'URI host "10.0.0.1" is not allowed',
        ];

        yield 'empty host' => [
            '',
            'URI host "" is not allowed',
        ];

        yield 'idn domain' => [
            'xn--n3h.com',
            'URI host "xn--n3h.com" is not allowed',
        ];
    }

    // =========================================================================
    // Security: XSS Prevention via URI Schemes
    // =========================================================================

    public function testBlockedSchemeForXssPrevention(): void
    {
        $xssSchemes = ['javascript', 'vbscript', 'data'];

        foreach ($xssSchemes as $scheme) {
            $exception = UnsafeUriException::blockedScheme($scheme);
            $this->assertStringContainsString($scheme, $exception->getMessage());
            $this->assertStringContainsString('not allowed', $exception->getMessage());
        }
    }

    // =========================================================================
    // Security: SSRF Prevention via Host Blocking
    // =========================================================================

    public function testBlockedHostForSsrfPrevention(): void
    {
        $ssrfHosts = ['127.0.0.1', 'localhost', '0.0.0.0', '169.254.169.254'];

        foreach ($ssrfHosts as $host) {
            $exception = UnsafeUriException::blockedHost($host);
            $this->assertStringContainsString($host, $exception->getMessage());
            $this->assertStringContainsString('not allowed', $exception->getMessage());
        }
    }

    // =========================================================================
    // Immutability: Each Call Creates New Instance
    // =========================================================================

    public function testFactoryMethodsCreateNewInstances(): void
    {
        $exception1 = UnsafeUriException::blockedScheme('javascript');
        $exception2 = UnsafeUriException::blockedScheme('javascript');

        $this->assertNotSame($exception1, $exception2);
    }

    public function testDifferentFactoryMethodsCreateDistinctExceptions(): void
    {
        $blockedScheme = UnsafeUriException::blockedScheme('javascript');
        $invalidUri    = UnsafeUriException::invalidUri('bad-uri');
        $blockedHost   = UnsafeUriException::blockedHost('evil.com');

        $this->assertNotSame($blockedScheme->getMessage(), $invalidUri->getMessage());
        $this->assertNotSame($blockedScheme->getMessage(), $blockedHost->getMessage());
        $this->assertNotSame($invalidUri->getMessage(), $blockedHost->getMessage());
    }
}
