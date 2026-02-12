<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\PermissionsPolicy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Exception\InvalidHeaderValueException;
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionDirective;
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionFeature;

#[CoversClass(PermissionDirective::class)]
final class PermissionDirectiveTest extends TestCase
{
    // ========== Constructor Tests ==========

    public function testConstructorWithEmptyAllowlist(): void
    {
        $directive = new PermissionDirective(PermissionFeature::CAMERA, []);

        $this->assertSame(PermissionFeature::CAMERA, $directive->feature);
        $this->assertSame([], $directive->allowlist());
        $this->assertTrue($directive->isBlocked());
    }

    public function testConstructorWithSelfKeyword(): void
    {
        $directive = new PermissionDirective(PermissionFeature::GEOLOCATION, ['self']);

        $this->assertSame(['self'], $directive->allowlist());
        $this->assertFalse($directive->isBlocked());
    }

    public function testConstructorWithWildcard(): void
    {
        $directive = new PermissionDirective(PermissionFeature::FULLSCREEN, ['*']);

        $this->assertSame(['*'], $directive->allowlist());
        $this->assertTrue($directive->allowsAll());
    }

    public function testConstructorWithValidOrigin(): void
    {
        $directive = new PermissionDirective(
            PermissionFeature::CAMERA,
            ['https://example.com']
        );

        $this->assertSame(['https://example.com'], $directive->allowlist());
    }

    public function testConstructorWithMultipleOrigins(): void
    {
        $directive = new PermissionDirective(
            PermissionFeature::MICROPHONE,
            ['self', 'https://example.com', 'https://trusted.org']
        );

        $this->assertCount(3, $directive->allowlist());
    }

    public function testConstructorWithOriginContainingPort(): void
    {
        $directive = new PermissionDirective(
            PermissionFeature::CAMERA,
            ['https://example.com:8443']
        );

        $this->assertSame(['https://example.com:8443'], $directive->allowlist());
    }

    // ========== Static Factory Tests ==========

    public function testBlockedFactory(): void
    {
        $directive = PermissionDirective::blocked(PermissionFeature::CAMERA);

        $this->assertSame(PermissionFeature::CAMERA, $directive->feature);
        $this->assertSame([], $directive->allowlist());
        $this->assertTrue($directive->isBlocked());
        $this->assertFalse($directive->allowsAll());
    }

    public function testSelfFactory(): void
    {
        $directive = PermissionDirective::self(PermissionFeature::GEOLOCATION);

        $this->assertSame(PermissionFeature::GEOLOCATION, $directive->feature);
        $this->assertSame(['self'], $directive->allowlist());
        $this->assertFalse($directive->isBlocked());
        $this->assertFalse($directive->allowsAll());
    }

    public function testAllFactory(): void
    {
        $directive = PermissionDirective::all(PermissionFeature::FULLSCREEN);

        $this->assertSame(PermissionFeature::FULLSCREEN, $directive->feature);
        $this->assertSame(['*'], $directive->allowlist());
        $this->assertFalse($directive->isBlocked());
        $this->assertTrue($directive->allowsAll());
    }

    public function testOriginsFactory(): void
    {
        $origins   = ['https://example.com', 'https://trusted.org'];
        $directive = PermissionDirective::origins(PermissionFeature::PAYMENT, $origins);

        $this->assertSame(PermissionFeature::PAYMENT, $directive->feature);
        $this->assertSame($origins, $directive->allowlist());
    }

    public function testOriginsFactoryWithMixedValues(): void
    {
        $directive = PermissionDirective::origins(
            PermissionFeature::CAMERA,
            ['self', 'https://example.com']
        );

        $this->assertSame(['self', 'https://example.com'], $directive->allowlist());
    }

    // ========== withOrigin Tests ==========

    public function testWithOriginAddsToAllowlist(): void
    {
        $original = PermissionDirective::self(PermissionFeature::CAMERA);
        $modified = $original->withOrigin('https://example.com');

        // Verify immutability
        $this->assertSame(['self'], $original->allowlist());
        $this->assertSame(['self', 'https://example.com'], $modified->allowlist());
        $this->assertNotSame($original, $modified);
    }

    public function testWithOriginReturnsNewInstance(): void
    {
        $original = PermissionDirective::blocked(PermissionFeature::GEOLOCATION);
        $modified = $original->withOrigin('https://maps.example.com');

        $this->assertNotSame($original, $modified);
        $this->assertTrue($original->isBlocked());
        $this->assertFalse($modified->isBlocked());
    }

    // ========== build() Tests ==========

    public function testBuildBlockedDirective(): void
    {
        $directive = PermissionDirective::blocked(PermissionFeature::CAMERA);

        $this->assertSame('camera=()', $directive->build());
    }

    public function testBuildSelfDirective(): void
    {
        $directive = PermissionDirective::self(PermissionFeature::GEOLOCATION);

        $this->assertSame('geolocation=(self)', $directive->build());
    }

    public function testBuildAllDirective(): void
    {
        $directive = PermissionDirective::all(PermissionFeature::FULLSCREEN);

        $this->assertSame('fullscreen=(*)', $directive->build());
    }

    public function testBuildWithSingleOrigin(): void
    {
        $directive = PermissionDirective::origins(
            PermissionFeature::CAMERA,
            ['https://example.com']
        );

        $this->assertSame('camera=("https://example.com")', $directive->build());
    }

    public function testBuildWithMultipleOrigins(): void
    {
        $directive = PermissionDirective::origins(
            PermissionFeature::MICROPHONE,
            ['https://example.com', 'https://trusted.org']
        );

        $this->assertSame(
            'microphone=("https://example.com" "https://trusted.org")',
            $directive->build()
        );
    }

    public function testBuildWithSelfAndOrigins(): void
    {
        $directive = PermissionDirective::origins(
            PermissionFeature::CAMERA,
            ['self', 'https://example.com']
        );

        $this->assertSame('camera=(self "https://example.com")', $directive->build());
    }

    public function testBuildWithWildcardAndOrigins(): void
    {
        // Unusual but valid: * with origins
        $directive = new PermissionDirective(
            PermissionFeature::FULLSCREEN,
            ['*', 'https://example.com']
        );

        $this->assertSame('fullscreen=(* "https://example.com")', $directive->build());
    }

    #[DataProvider('allFeaturesProvider')]
    public function testBuildUsesCorrectDirectiveName(PermissionFeature $feature): void
    {
        $directive = PermissionDirective::blocked($feature);

        $this->assertStringStartsWith($feature->directiveName() . '=(', $directive->build());
    }

    /**
     * @return iterable<string, array{feature: PermissionFeature}>
     */
    public static function allFeaturesProvider(): iterable
    {
        foreach (PermissionFeature::cases() as $feature) {
            yield $feature->name => ['feature' => $feature];
        }
    }

    // ========== Validation Tests - Header Injection Prevention ==========

    public function testRejectsNewlineInOrigin(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('control character');

        new PermissionDirective(
            PermissionFeature::CAMERA,
            ["https://example.com\nX-Injected: evil"]
        );
    }

    public function testRejectsCarriageReturnInOrigin(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('control character');

        new PermissionDirective(
            PermissionFeature::CAMERA,
            ["https://example.com\rX-Injected: evil"]
        );
    }

    public function testRejectsCrLfInOrigin(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('control character');

        new PermissionDirective(
            PermissionFeature::CAMERA,
            ["https://example.com\r\nX-Injected: evil"]
        );
    }

    #[DataProvider('headerInjectionAttemptsProvider')]
    public function testRejectsHeaderInjectionAttempts(string $maliciousOrigin): void
    {
        $this->expectException(InvalidHeaderValueException::class);

        new PermissionDirective(PermissionFeature::CAMERA, [$maliciousOrigin]);
    }

    /**
     * @return iterable<string, array{maliciousOrigin: string}>
     */
    public static function headerInjectionAttemptsProvider(): iterable
    {
        yield 'LF in origin' => [
            'maliciousOrigin' => "https://example.com\nSet-Cookie: session=stolen",
        ];

        yield 'CR in origin' => [
            'maliciousOrigin' => "https://example.com\rSet-Cookie: session=stolen",
        ];

        yield 'CRLF in origin' => [
            'maliciousOrigin' => "https://example.com\r\nSet-Cookie: session=stolen",
        ];

        yield 'multiple newlines' => [
            'maliciousOrigin' => "https://example.com\n\nBody injection",
        ];

        yield 'null byte with newline' => [
            'maliciousOrigin' => "https://example.com\x00\ninjection",
        ];
    }

    // ========== Validation Tests - Invalid Origins ==========

    public function testRejectsOriginWithPath(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('Invalid origin');

        new PermissionDirective(
            PermissionFeature::CAMERA,
            ['https://example.com/path/to/resource']
        );
    }

    public function testRejectsOriginWithQuery(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('Invalid origin');

        new PermissionDirective(
            PermissionFeature::CAMERA,
            ['https://example.com?param=value']
        );
    }

    public function testRejectsOriginWithFragment(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('Invalid origin');

        new PermissionDirective(
            PermissionFeature::CAMERA,
            ['https://example.com#fragment']
        );
    }

    public function testRejectsOriginWithoutScheme(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('Invalid origin');

        new PermissionDirective(
            PermissionFeature::CAMERA,
            ['example.com']
        );
    }

    public function testRejectsOriginWithoutHost(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('Invalid origin');

        new PermissionDirective(
            PermissionFeature::CAMERA,
            ['https://']
        );
    }

    public function testRejectsInvalidOriginFormat(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('Invalid origin');

        new PermissionDirective(
            PermissionFeature::CAMERA,
            ['not-a-valid-origin']
        );
    }

    #[DataProvider('invalidOriginsProvider')]
    public function testRejectsInvalidOrigins(string $invalidOrigin): void
    {
        $this->expectException(InvalidHeaderValueException::class);

        new PermissionDirective(PermissionFeature::CAMERA, [$invalidOrigin]);
    }

    /**
     * @return iterable<string, array{invalidOrigin: string}>
     */
    public static function invalidOriginsProvider(): iterable
    {
        yield 'path without root' => [
            'invalidOrigin' => 'https://example.com/path',
        ];

        yield 'query string' => [
            'invalidOrigin' => 'https://example.com?query=1',
        ];

        yield 'fragment' => [
            'invalidOrigin' => 'https://example.com#anchor',
        ];

        yield 'missing scheme' => [
            'invalidOrigin' => '//example.com',
        ];

        yield 'missing host' => [
            'invalidOrigin' => 'https://',
        ];

        yield 'bare hostname' => [
            'invalidOrigin' => 'example.com',
        ];

        yield 'javascript URI' => [
            'invalidOrigin' => 'javascript:alert(1)',
        ];

        yield 'data URI' => [
            'invalidOrigin' => 'data:text/html,<script>alert(1)</script>',
        ];

        yield 'relative path' => [
            'invalidOrigin' => '/path/to/resource',
        ];

        yield 'empty string' => [
            'invalidOrigin' => '',
        ];
    }

    // ========== Valid Origins Tests ==========

    #[DataProvider('validOriginsProvider')]
    public function testAcceptsValidOrigins(string $validOrigin): void
    {
        $directive = new PermissionDirective(PermissionFeature::CAMERA, [$validOrigin]);

        $this->assertContains($validOrigin, $directive->allowlist());
    }

    /**
     * @return iterable<string, array{validOrigin: string}>
     */
    public static function validOriginsProvider(): iterable
    {
        yield 'https origin' => [
            'validOrigin' => 'https://example.com',
        ];

        yield 'http origin' => [
            'validOrigin' => 'http://localhost',
        ];

        yield 'with port' => [
            'validOrigin' => 'https://example.com:8443',
        ];

        yield 'localhost with port' => [
            'validOrigin' => 'http://localhost:3000',
        ];

        yield 'subdomain' => [
            'validOrigin' => 'https://sub.example.com',
        ];

        yield 'deep subdomain' => [
            'validOrigin' => 'https://a.b.c.example.com',
        ];

        yield 'IP address' => [
            'validOrigin' => 'http://192.168.1.1',
        ];

        yield 'IP with port' => [
            'validOrigin' => 'http://192.168.1.1:8080',
        ];

        yield 'origin with trailing slash' => [
            'validOrigin' => 'https://example.com/',
        ];
    }

    // ========== Reserved Keywords Tests ==========

    public function testSelfKeywordNotValidatedAsOrigin(): void
    {
        $directive = new PermissionDirective(PermissionFeature::CAMERA, ['self']);

        $this->assertSame(['self'], $directive->allowlist());
    }

    public function testWildcardNotValidatedAsOrigin(): void
    {
        $directive = new PermissionDirective(PermissionFeature::CAMERA, ['*']);

        $this->assertSame(['*'], $directive->allowlist());
    }

    // ========== withOrigin Validation Tests ==========

    public function testWithOriginValidatesOrigin(): void
    {
        $directive = PermissionDirective::self(PermissionFeature::CAMERA);

        $this->expectException(InvalidHeaderValueException::class);

        $directive->withOrigin("https://evil.com\nX-Injected: malicious");
    }

    public function testWithOriginRejectsInvalidOriginFormat(): void
    {
        $directive = PermissionDirective::self(PermissionFeature::CAMERA);

        $this->expectException(InvalidHeaderValueException::class);

        $directive->withOrigin('not-a-valid-origin');
    }

    // ========== Immutability Tests ==========

    public function testDirectiveIsImmutable(): void
    {
        $original = PermissionDirective::self(PermissionFeature::CAMERA);

        // All mutation methods return new instances
        $modified = $original->withOrigin('https://example.com');

        $this->assertNotSame($original, $modified);
        $this->assertSame(['self'], $original->allowlist());
        $this->assertSame(['self', 'https://example.com'], $modified->allowlist());
    }

    // ========== Edge Cases ==========

    public function testEmptyOriginIsRejected(): void
    {
        $this->expectException(InvalidHeaderValueException::class);

        new PermissionDirective(PermissionFeature::CAMERA, ['']);
    }

    public function testOriginsFactoryWithEmptyArrayCreatesBlockedDirective(): void
    {
        $directive = PermissionDirective::origins(PermissionFeature::CAMERA, []);

        $this->assertTrue($directive->isBlocked());
        $this->assertSame('camera=()', $directive->build());
    }
}
