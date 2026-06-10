<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Cors;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cors\CorsConfig;

#[CoversClass(CorsConfig::class)]
final class CorsConfigTest extends TestCase
{
    #[Test]
    public function testDefaultsAreRestrictive(): void
    {
        $config = new CorsConfig();

        self::assertSame([], $config->allowedOrigins);
        self::assertSame(['GET', 'HEAD', 'POST'], $config->allowedMethods);
        self::assertSame([], $config->allowedHeaders);
        self::assertSame([], $config->exposedHeaders);
        self::assertFalse($config->allowCredentials);
        self::assertSame(0, $config->maxAge);
    }

    #[Test]
    public function testNegativeMaxAgeIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Max age must be greater than or equal to 0');

        new CorsConfig(maxAge: -1);
    }

    #[Test]
    public function testWildcardWithCredentialsIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Wildcard origin "*" cannot be combined with credentials');

        new CorsConfig(allowedOrigins: ['*'], allowCredentials: true);
    }

    #[Test]
    public function testWithCredentialsRejectsWildcardOrigin(): void
    {
        $config = new CorsConfig(allowedOrigins: ['*']);

        $this->expectException(InvalidArgumentException::class);

        $config->withCredentials();
    }

    #[Test]
    public function testCarriageReturnInOriginIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('CORS origin must not contain CR or LF characters');

        new CorsConfig(allowedOrigins: ["https://example.com\r"]);
    }

    #[Test]
    public function testNewlineInMethodIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('CORS method must not contain CR or LF characters');

        new CorsConfig(allowedMethods: ["GET\n"]);
    }

    #[Test]
    public function testNewlineInHeaderIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('CORS header must not contain CR or LF characters');

        new CorsConfig(allowedHeaders: ["X-Test\n"]);
    }

    #[Test]
    public function testNewlineInExposedHeaderIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('CORS exposed header must not contain CR or LF characters');

        new CorsConfig(exposedHeaders: ["X-Test\n"]);
    }

    #[Test]
    public function testWithAllowedOriginsReturnsNewInstance(): void
    {
        $config  = new CorsConfig();
        $changed = $config->withAllowedOrigins(['https://example.com']);

        self::assertNotSame($config, $changed);
        self::assertSame([], $config->allowedOrigins);
        self::assertSame(['https://example.com'], $changed->allowedOrigins);
    }

    #[Test]
    public function testWithAllowedMethodsReturnsNewInstance(): void
    {
        $changed = (new CorsConfig())->withAllowedMethods(['PUT']);

        self::assertSame(['PUT'], $changed->allowedMethods);
    }

    #[Test]
    public function testWithAllowedHeadersReturnsNewInstance(): void
    {
        $changed = (new CorsConfig())->withAllowedHeaders(['X-Custom']);

        self::assertSame(['X-Custom'], $changed->allowedHeaders);
    }

    #[Test]
    public function testWithExposedHeadersReturnsNewInstance(): void
    {
        $changed = (new CorsConfig())->withExposedHeaders(['X-Total-Count']);

        self::assertSame(['X-Total-Count'], $changed->exposedHeaders);
    }

    #[Test]
    public function testWithCredentialsReturnsNewInstance(): void
    {
        $config  = new CorsConfig(allowedOrigins: ['https://example.com']);
        $changed = $config->withCredentials();

        self::assertFalse($config->allowCredentials);
        self::assertTrue($changed->allowCredentials);
    }

    #[Test]
    public function testWithMaxAgeReturnsNewInstance(): void
    {
        $changed = (new CorsConfig())->withMaxAge(600);

        self::assertSame(600, $changed->maxAge);
    }

    #[Test]
    public function testWithMaxAgeRejectsNegativeValue(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new CorsConfig())->withMaxAge(-1);
    }

    #[Test]
    public function testAllowsAnyOrigin(): void
    {
        self::assertTrue((new CorsConfig(allowedOrigins: ['*']))->allowsAnyOrigin());
        self::assertFalse((new CorsConfig(allowedOrigins: ['https://example.com']))->allowsAnyOrigin());
    }

    #[Test]
    public function testIsOriginAllowedWithWildcard(): void
    {
        $config = new CorsConfig(allowedOrigins: ['*']);

        self::assertTrue($config->isOriginAllowed('https://anything.test'));
    }

    #[Test]
    public function testIsOriginAllowedWithExactMatch(): void
    {
        $config = new CorsConfig(allowedOrigins: ['https://example.com', 'https://app.example.com']);

        self::assertTrue($config->isOriginAllowed('https://app.example.com'));
        self::assertFalse($config->isOriginAllowed('https://evil.com'));
    }

    #[Test]
    public function testIsOriginAllowedWithSubdomainPattern(): void
    {
        $config = new CorsConfig(allowedOrigins: ['https://*.example.com']);

        self::assertTrue($config->isOriginAllowed('https://api.example.com'));
        self::assertTrue($config->isOriginAllowed('https://app.example.com'));
        self::assertFalse($config->isOriginAllowed('https://example.org'));
        self::assertFalse($config->isOriginAllowed('https://example.com.evil.com/'));
    }

    #[Test]
    public function testResolveAllowOriginReturnsWildcardWhenAnyOriginAllowed(): void
    {
        $config = new CorsConfig(allowedOrigins: ['*']);

        self::assertSame('*', $config->resolveAllowOrigin('https://anything.test'));
    }

    #[Test]
    public function testResolveAllowOriginEchoesOriginForSpecificOrigins(): void
    {
        $config = new CorsConfig(allowedOrigins: ['https://example.com']);

        self::assertSame('https://example.com', $config->resolveAllowOrigin('https://example.com'));
    }

    #[Test]
    public function testResolveAllowOriginEchoesOriginWhenCredentialsEnabled(): void
    {
        $config = new CorsConfig(allowedOrigins: ['https://example.com'], allowCredentials: true);

        self::assertSame('https://example.com', $config->resolveAllowOrigin('https://example.com'));
    }

    #[Test]
    public function testResolveAllowOriginReturnsNullForDisallowedOrigin(): void
    {
        $config = new CorsConfig(allowedOrigins: ['https://example.com']);

        self::assertNull($config->resolveAllowOrigin('https://evil.com'));
    }

    #[Test]
    public function testPermissivePreset(): void
    {
        $config = CorsConfig::permissive();

        self::assertSame(['*'], $config->allowedOrigins);
        self::assertSame(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], $config->allowedMethods);
        self::assertSame(['Content-Type', 'Authorization'], $config->allowedHeaders);
        self::assertFalse($config->allowCredentials);
        self::assertSame('*', $config->resolveAllowOrigin('https://anything.test'));
    }

    #[Test]
    public function testForOriginsPreset(): void
    {
        $config = CorsConfig::forOrigins(['https://a.com', 'https://b.com']);

        self::assertSame(['https://a.com', 'https://b.com'], $config->allowedOrigins);
        self::assertSame(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], $config->allowedMethods);
        self::assertSame(['Content-Type', 'Authorization'], $config->allowedHeaders);
        self::assertTrue($config->isOriginAllowed('https://b.com'));
        self::assertFalse($config->isOriginAllowed('https://c.com'));
    }
}
