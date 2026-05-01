<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\CsrfConfig;

#[CoversClass(CsrfConfig::class)]
final class CsrfConfigTest extends TestCase
{
    #[Test]
    public function testDefaultValues(): void
    {
        $config = new CsrfConfig();

        $this->assertSame('_csrf_token', $config->fieldName);
        $this->assertSame('X-CSRF-Token', $config->headerName);
        $this->assertSame('csrf_token', $config->cookieName);
        $this->assertSame(7200, $config->ttl);
        $this->assertFalse($config->rotateOnValidation);
        $this->assertFalse($config->singleUse);
    }

    #[Test]
    public function testCustomValues(): void
    {
        $config = new CsrfConfig(
            fieldName: '_token',
            headerName: 'X-Token',
            cookieName: 'token',
            ttl: 3600,
            rotateOnValidation: true,
            singleUse: true
        );

        $this->assertSame('_token', $config->fieldName);
        $this->assertSame('X-Token', $config->headerName);
        $this->assertSame('token', $config->cookieName);
        $this->assertSame(3600, $config->ttl);
        $this->assertTrue($config->rotateOnValidation);
        $this->assertTrue($config->singleUse);
    }

    #[Test]
    public function testWithFieldName(): void
    {
        $config    = new CsrfConfig();
        $newConfig = $config->withFieldName('_token');

        $this->assertSame('_csrf_token', $config->fieldName);
        $this->assertSame('_token', $newConfig->fieldName);
        $this->assertNotSame($config, $newConfig);
    }

    #[Test]
    public function testWithHeaderName(): void
    {
        $config    = new CsrfConfig();
        $newConfig = $config->withHeaderName('X-Token');

        $this->assertSame('X-CSRF-Token', $config->headerName);
        $this->assertSame('X-Token', $newConfig->headerName);
    }

    #[Test]
    public function testWithCookieName(): void
    {
        $config    = new CsrfConfig();
        $newConfig = $config->withCookieName('token');

        $this->assertSame('csrf_token', $config->cookieName);
        $this->assertSame('token', $newConfig->cookieName);
    }

    #[Test]
    public function testWithTtl(): void
    {
        $config    = new CsrfConfig();
        $newConfig = $config->withTtl(1800);

        $this->assertSame(7200, $config->ttl);
        $this->assertSame(1800, $newConfig->ttl);
    }

    #[Test]
    public function testWithRotateOnValidation(): void
    {
        $config    = new CsrfConfig();
        $newConfig = $config->withRotateOnValidation();

        $this->assertFalse($config->rotateOnValidation);
        $this->assertTrue($newConfig->rotateOnValidation);
    }

    #[Test]
    public function testWithoutRotateOnValidation(): void
    {
        $config    = new CsrfConfig(rotateOnValidation: true);
        $newConfig = $config->withoutRotateOnValidation();

        $this->assertTrue($config->rotateOnValidation);
        $this->assertFalse($newConfig->rotateOnValidation);
    }

    #[Test]
    public function testWithSingleUse(): void
    {
        $config    = new CsrfConfig();
        $newConfig = $config->withSingleUse();

        $this->assertFalse($config->singleUse);
        $this->assertTrue($newConfig->singleUse);
    }

    #[Test]
    public function testWithoutSingleUse(): void
    {
        $config    = new CsrfConfig(singleUse: true);
        $newConfig = $config->withoutSingleUse();

        $this->assertTrue($config->singleUse);
        $this->assertFalse($newConfig->singleUse);
    }

    #[Test]
    public function testStrictFactory(): void
    {
        $config = CsrfConfig::strict();

        $this->assertSame(1800, $config->ttl);
        $this->assertTrue($config->singleUse);
    }

    #[Test]
    public function testDefaultFactory(): void
    {
        $config = CsrfConfig::default();

        $this->assertSame(7200, $config->ttl);
        $this->assertFalse($config->singleUse);
        $this->assertFalse($config->rotateOnValidation);
    }

    #[Test]
    public function testImmutability(): void
    {
        $original = new CsrfConfig();

        $original->withFieldName('_token');
        $original->withHeaderName('X-Token');
        $original->withCookieName('token');
        $original->withTtl(3600);
        $original->withRotateOnValidation();
        $original->withSingleUse();

        $this->assertSame('_csrf_token', $original->fieldName);
        $this->assertSame('X-CSRF-Token', $original->headerName);
        $this->assertSame('csrf_token', $original->cookieName);
        $this->assertSame(7200, $original->ttl);
        $this->assertFalse($original->rotateOnValidation);
        $this->assertFalse($original->singleUse);
    }

    #[Test]
    public function testChainedModifications(): void
    {
        $config = (new CsrfConfig())
            ->withFieldName('_token')
            ->withHeaderName('X-Token')
            ->withTtl(3600)
            ->withRotateOnValidation();

        $this->assertSame('_token', $config->fieldName);
        $this->assertSame('X-Token', $config->headerName);
        $this->assertSame(3600, $config->ttl);
        $this->assertTrue($config->rotateOnValidation);
    }

    #[Test]
    public function testConstants(): void
    {
        $this->assertSame(7200, CsrfConfig::DEFAULT_TTL);
        $this->assertSame('_csrf_token', CsrfConfig::DEFAULT_FIELD_NAME);
        $this->assertSame('X-CSRF-Token', CsrfConfig::DEFAULT_HEADER_NAME);
        $this->assertSame('csrf_token', CsrfConfig::DEFAULT_COOKIE_NAME);
    }
}
