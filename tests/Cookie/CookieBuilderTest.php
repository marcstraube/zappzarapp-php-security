<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Cookie;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cookie\CookieBuilder;
use Zappzarapp\Security\Cookie\CookieOptions;
use Zappzarapp\Security\Cookie\CookieValidator;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieNameException;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieValueException;
use Zappzarapp\Security\Cookie\SameSitePolicy;
use Zappzarapp\Security\Cookie\SecureCookie;

#[CoversClass(CookieBuilder::class)]
#[UsesClass(CookieOptions::class)]
#[UsesClass(CookieValidator::class)]
#[UsesClass(SecureCookie::class)]
#[UsesClass(InvalidCookieNameException::class)]
#[UsesClass(InvalidCookieValueException::class)]
#[UsesClass(SameSitePolicy::class)]
final class CookieBuilderTest extends TestCase
{
    #[Test]
    public function testCreateFactoryMethod(): void
    {
        $builder = CookieBuilder::create('session', 'abc123');

        $this->assertInstanceOf(CookieBuilder::class, $builder);
    }

    #[Test]
    public function testConstructor(): void
    {
        $builder = new CookieBuilder('name', 'value');

        $this->assertInstanceOf(CookieBuilder::class, $builder);
    }

    #[Test]
    public function testConstructorWithDefaultEmptyValue(): void
    {
        $builder = new CookieBuilder('name');
        $cookie  = $builder->build();

        $this->assertSame('', $cookie->value);
    }

    #[Test]
    public function testBuildReturnsSecureCookie(): void
    {
        $builder = CookieBuilder::create('session', 'abc123');
        $cookie  = $builder->build();

        $this->assertInstanceOf(SecureCookie::class, $cookie);
        $this->assertSame('session', $cookie->name);
        $this->assertSame('abc123', $cookie->value);
    }

    #[Test]
    public function testBuildWithSecureDefaults(): void
    {
        $cookie = CookieBuilder::create('session', 'value')->build();

        $this->assertTrue($cookie->options->secure);
        $this->assertTrue($cookie->options->httpOnly);
        $this->assertSame(SameSitePolicy::STRICT, $cookie->options->sameSite);
        $this->assertSame('/', $cookie->options->path);
        $this->assertSame('', $cookie->options->domain);
        $this->assertSame(0, $cookie->options->expires);
    }

    #[Test]
    public function testValueMethod(): void
    {
        $cookie = CookieBuilder::create('name')
            ->value('updated_value')
            ->build();

        $this->assertSame('updated_value', $cookie->value);
    }

    #[Test]
    public function testExpiresMethod(): void
    {
        $timestamp = time() + 3600;
        $cookie    = CookieBuilder::create('name', 'value')
            ->expires($timestamp)
            ->build();

        $this->assertSame($timestamp, $cookie->options->expires);
    }

    #[Test]
    public function testMaxAgeMethod(): void
    {
        $now     = time();
        $seconds = 7200;
        $cookie  = CookieBuilder::create('name', 'value')
            ->maxAge($seconds)
            ->build();

        $this->assertGreaterThanOrEqual($now + $seconds, $cookie->options->expires);
        $this->assertLessThanOrEqual($now + $seconds + 2, $cookie->options->expires);
    }

    #[Test]
    public function testPathMethod(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->path('/admin')
            ->build();

        $this->assertSame('/admin', $cookie->options->path);
    }

    #[Test]
    public function testDomainMethod(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->domain('example.com')
            ->build();

        $this->assertSame('example.com', $cookie->options->domain);
    }

    #[Test]
    public function testSecureMethodEnables(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->secure(false)
            ->secure(true)
            ->build();

        $this->assertTrue($cookie->options->secure);
    }

    #[Test]
    public function testSecureMethodDisables(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->secure(false)
            ->build();

        $this->assertFalse($cookie->options->secure);
    }

    #[Test]
    public function testSecureMethodDefaultsToTrue(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->secure()
            ->build();

        $this->assertTrue($cookie->options->secure);
    }

    #[Test]
    public function testHttpOnlyMethodEnables(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->httpOnly(false)
            ->httpOnly(true)
            ->build();

        $this->assertTrue($cookie->options->httpOnly);
    }

    #[Test]
    public function testHttpOnlyMethodDisables(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->httpOnly(false)
            ->build();

        $this->assertFalse($cookie->options->httpOnly);
    }

    #[Test]
    public function testHttpOnlyMethodDefaultsToTrue(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->httpOnly()
            ->build();

        $this->assertTrue($cookie->options->httpOnly);
    }

    #[Test]
    public function testSameSiteMethod(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->sameSite(SameSitePolicy::LAX)
            ->build();

        $this->assertSame(SameSitePolicy::LAX, $cookie->options->sameSite);
    }

    #[Test]
    public function testSameSiteNone(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->sameSite(SameSitePolicy::NONE)
            ->build();

        $this->assertSame(SameSitePolicy::NONE, $cookie->options->sameSite);
    }

    #[Test]
    public function testStrictPreset(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->secure(false)
            ->httpOnly(false)
            ->sameSite(SameSitePolicy::NONE)
            ->strict()
            ->build();

        $this->assertTrue($cookie->options->secure);
        $this->assertTrue($cookie->options->httpOnly);
        $this->assertSame(SameSitePolicy::STRICT, $cookie->options->sameSite);
    }

    #[Test]
    public function testLaxPreset(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->lax()
            ->build();

        $this->assertTrue($cookie->options->secure);
        $this->assertTrue($cookie->options->httpOnly);
        $this->assertSame(SameSitePolicy::LAX, $cookie->options->sameSite);
    }

    #[Test]
    public function testDevelopmentPreset(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->development()
            ->build();

        $this->assertFalse($cookie->options->secure);
        $this->assertTrue($cookie->options->httpOnly);
        $this->assertSame(SameSitePolicy::LAX, $cookie->options->sameSite);
    }

    #[Test]
    public function testFluentApiChaining(): void
    {
        $now    = time();
        $cookie = CookieBuilder::create('session_id', 'token123')
            ->expires($now + 86400)
            ->path('/app')
            ->domain('.example.com')
            ->secure(true)
            ->httpOnly(true)
            ->sameSite(SameSitePolicy::LAX)
            ->build();

        $this->assertSame('session_id', $cookie->name);
        $this->assertSame('token123', $cookie->value);
        $this->assertSame($now + 86400, $cookie->options->expires);
        $this->assertSame('/app', $cookie->options->path);
        $this->assertSame('.example.com', $cookie->options->domain);
        $this->assertTrue($cookie->options->secure);
        $this->assertTrue($cookie->options->httpOnly);
        $this->assertSame(SameSitePolicy::LAX, $cookie->options->sameSite);
    }

    #[Test]
    public function testBuildThrowsOnInvalidName(): void
    {
        $this->expectException(InvalidCookieNameException::class);

        CookieBuilder::create('invalid;name', 'value')->build();
    }

    #[Test]
    public function testBuildThrowsOnEmptyName(): void
    {
        $this->expectException(InvalidCookieNameException::class);

        CookieBuilder::create('', 'value')->build();
    }

    #[Test]
    public function testBuildThrowsOnInvalidValue(): void
    {
        $this->expectException(InvalidCookieValueException::class);

        CookieBuilder::create('name', "value\ninjection")->build();
    }

    #[Test]
    public function testValueMethodWithInvalidValueThrowsOnBuild(): void
    {
        $this->expectException(InvalidCookieValueException::class);

        CookieBuilder::create('name')
            ->value("invalid;value")
            ->build();
    }

    #[Test]
    public function testSendMethod(): void
    {
        // Note: send() uses setcookie() internally.
        // In CLI environment, setcookie() may succeed (returns true) even though
        // no actual HTTP headers are sent. The behavior depends on PHP version
        // and SAPI configuration.
        //
        // This test verifies that send() can be called and returns a boolean.
        // For actual cookie sending verification, integration tests are needed.

        $builder = CookieBuilder::create('test', 'value');
        $result  = $builder->send();

        $this->assertIsBool($result);
    }

    #[Test]
    public function testSendThrowsOnInvalidName(): void
    {
        $this->expectException(InvalidCookieNameException::class);

        CookieBuilder::create('invalid=name', 'value')->send();
    }

    #[Test]
    public function testSendThrowsOnInvalidValue(): void
    {
        $this->expectException(InvalidCookieValueException::class);

        CookieBuilder::create('name', "value\rinjection")->send();
    }

    #[Test]
    public function testMultipleBuildsProduceIndependentCookies(): void
    {
        $builder = CookieBuilder::create('name', 'value1');
        $cookie1 = $builder->build();

        $builder->value('value2');
        $cookie2 = $builder->build();

        $this->assertSame('value1', $cookie1->value);
        $this->assertSame('value2', $cookie2->value);
        $this->assertNotSame($cookie1, $cookie2);
    }

    #[Test]
    public function testBuilderCanBeReused(): void
    {
        $builder = CookieBuilder::create('session', 'initial')
            ->path('/app')
            ->secure(true);

        $cookie1 = $builder->build();

        $builder->value('updated')
            ->domain('example.com');

        $cookie2 = $builder->build();

        $this->assertSame('initial', $cookie1->value);
        $this->assertSame('updated', $cookie2->value);
        $this->assertSame('', $cookie1->options->domain);
        $this->assertSame('example.com', $cookie2->options->domain);
    }

    #[Test]
    public function testPathDefaultsToRoot(): void
    {
        $cookie = CookieBuilder::create('name', 'value')->build();

        $this->assertSame('/', $cookie->options->path);
    }

    #[Test]
    public function testDomainDefaultsToEmpty(): void
    {
        $cookie = CookieBuilder::create('name', 'value')->build();

        $this->assertSame('', $cookie->options->domain);
    }

    #[Test]
    public function testExpiresDefaultsToZero(): void
    {
        $cookie = CookieBuilder::create('name', 'value')->build();

        $this->assertSame(0, $cookie->options->expires);
    }

    #[Test]
    public function testOverridingPresetsWithIndividualSettings(): void
    {
        $cookie = CookieBuilder::create('name', 'value')
            ->development()
            ->secure(true) // Override development's secure=false
            ->build();

        $this->assertTrue($cookie->options->secure);
        $this->assertTrue($cookie->options->httpOnly); // From development
        $this->assertSame(SameSitePolicy::LAX, $cookie->options->sameSite); // From development
    }

    #[Test]
    public function testComplexRealWorldScenario(): void
    {
        $now = time();

        // Session cookie
        $session = CookieBuilder::create('PHPSESSID', bin2hex(random_bytes(16)))
            ->strict()
            ->build();

        $this->assertTrue($session->options->secure);
        $this->assertTrue($session->options->httpOnly);
        $this->assertSame(SameSitePolicy::STRICT, $session->options->sameSite);
        $this->assertSame(0, $session->options->expires); // Session cookie

        // Remember me cookie
        $remember = CookieBuilder::create('remember_token', 'encrypted_token')
            ->maxAge(30 * 24 * 3600) // 30 days
            ->lax()
            ->build();

        $this->assertGreaterThan($now, $remember->options->expires);
        $this->assertSame(SameSitePolicy::LAX, $remember->options->sameSite);

        // Development cookie
        $dev = CookieBuilder::create('debug', 'true')
            ->development()
            ->build();

        $this->assertFalse($dev->options->secure);
    }
}
