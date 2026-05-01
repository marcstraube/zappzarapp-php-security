<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\Hsts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Exception\InvalidHeaderValueException;
use Zappzarapp\Security\Headers\Hsts\HstsConfig;

#[CoversClass(HstsConfig::class)]
final class HstsConfigTest extends TestCase
{
    #[Test]
    public function testDefaultValues(): void
    {
        $config = new HstsConfig();

        $this->assertSame(63072000, $config->maxAge);
        $this->assertTrue($config->includeSubDomains);
        $this->assertFalse($config->preload);
    }

    #[Test]
    public function testCustomValues(): void
    {
        // For preload=true, max-age must be >= 31536000
        $config = new HstsConfig(
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        );

        $this->assertSame(31536000, $config->maxAge);
        $this->assertTrue($config->includeSubDomains);
        $this->assertTrue($config->preload);
    }

    #[Test]
    public function testPreloadRequiresIncludeSubDomains(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('includeSubDomains');

        new HstsConfig(
            maxAge: 86400,
            includeSubDomains: false,
            preload: true
        );
    }

    #[Test]
    public function testPreloadRequiresMinMaxAge(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('max-age');

        new HstsConfig(
            maxAge: 86400,
            includeSubDomains: true,
            preload: true
        );
    }

    #[Test]
    public function testNegativeMaxAgeThrows(): void
    {
        $this->expectException(InvalidHeaderValueException::class);
        $this->expectExceptionMessage('max-age');

        new HstsConfig(maxAge: -1);
    }

    #[Test]
    public function testZeroMaxAgeAllowed(): void
    {
        $config = new HstsConfig(maxAge: 0, includeSubDomains: false);

        $this->assertSame(0, $config->maxAge);
    }

    #[Test]
    public function testWithMaxAge(): void
    {
        $config    = new HstsConfig();
        $newConfig = $config->withMaxAge(86400);

        $this->assertSame(63072000, $config->maxAge);
        $this->assertSame(86400, $newConfig->maxAge);
        $this->assertNotSame($config, $newConfig);
    }

    #[Test]
    public function testWithMaxAgeNegativeThrows(): void
    {
        $config = new HstsConfig();

        $this->expectException(InvalidHeaderValueException::class);

        $config->withMaxAge(-1);
    }

    #[Test]
    public function testWithIncludeSubDomains(): void
    {
        $config    = new HstsConfig(includeSubDomains: false);
        $newConfig = $config->withIncludeSubDomains();

        $this->assertFalse($config->includeSubDomains);
        $this->assertTrue($newConfig->includeSubDomains);
    }

    #[Test]
    public function testWithoutIncludeSubDomains(): void
    {
        $config    = new HstsConfig();
        $newConfig = $config->withoutIncludeSubDomains();

        $this->assertTrue($config->includeSubDomains);
        $this->assertFalse($newConfig->includeSubDomains);
    }

    #[Test]
    public function testWithPreload(): void
    {
        $config    = new HstsConfig();
        $newConfig = $config->withPreload();

        $this->assertFalse($config->preload);
        $this->assertTrue($newConfig->preload);
    }

    #[Test]
    public function testWithoutPreload(): void
    {
        $config    = HstsConfig::preload();
        $newConfig = $config->withoutPreload();

        $this->assertTrue($config->preload);
        $this->assertFalse($newConfig->preload);
    }

    #[Test]
    public function testHeaderValueBasic(): void
    {
        $config = new HstsConfig(
            maxAge: 31536000,
            includeSubDomains: false,
            preload: false
        );

        $this->assertSame('max-age=31536000', $config->headerValue());
    }

    #[Test]
    public function testHeaderValueWithIncludeSubDomains(): void
    {
        $config = new HstsConfig(
            maxAge: 31536000,
            includeSubDomains: true,
            preload: false
        );

        $this->assertSame('max-age=31536000; includeSubDomains', $config->headerValue());
    }

    #[Test]
    public function testHeaderValueWithPreload(): void
    {
        $config = new HstsConfig(
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        );

        $this->assertSame('max-age=31536000; includeSubDomains; preload', $config->headerValue());
    }

    #[Test]
    public function testStrictFactory(): void
    {
        $config = HstsConfig::strict();

        $this->assertSame(63072000, $config->maxAge);
        $this->assertTrue($config->includeSubDomains);
        $this->assertFalse($config->preload);
    }

    #[Test]
    public function testPreloadFactory(): void
    {
        $config = HstsConfig::preload();

        $this->assertSame(63072000, $config->maxAge);
        $this->assertTrue($config->includeSubDomains);
        $this->assertTrue($config->preload);
    }

    #[Test]
    public function testTestingFactory(): void
    {
        $config = HstsConfig::testing();

        $this->assertSame(300, $config->maxAge);
        $this->assertFalse($config->includeSubDomains);
        $this->assertFalse($config->preload);
    }

    #[Test]
    public function testDisabledFactory(): void
    {
        $config = HstsConfig::disabled();

        $this->assertSame(0, $config->maxAge);
        $this->assertFalse($config->includeSubDomains);
        $this->assertFalse($config->preload);
    }

    #[Test]
    public function testImmutability(): void
    {
        $original = new HstsConfig();

        $original->withMaxAge(86400);
        $original->withoutIncludeSubDomains();
        $original->withPreload();

        $this->assertSame(63072000, $original->maxAge);
        $this->assertTrue($original->includeSubDomains);
        $this->assertFalse($original->preload);
    }

    #[Test]
    public function testConstants(): void
    {
        $this->assertSame(31536000, HstsConfig::PRELOAD_MIN_MAX_AGE);
        $this->assertSame(63072000, HstsConfig::RECOMMENDED_MAX_AGE);
    }
}
