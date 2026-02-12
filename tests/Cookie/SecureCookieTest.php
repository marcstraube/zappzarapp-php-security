<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Cookie;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cookie\CookieOptions;
use Zappzarapp\Security\Cookie\CookieValidator;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieNameException;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieValueException;
use Zappzarapp\Security\Cookie\SameSitePolicy;
use Zappzarapp\Security\Cookie\SecureCookie;

#[CoversClass(SecureCookie::class)]
#[UsesClass(CookieOptions::class)]
#[UsesClass(CookieValidator::class)]
#[UsesClass(InvalidCookieNameException::class)]
#[UsesClass(InvalidCookieValueException::class)]
#[UsesClass(SameSitePolicy::class)]
final class SecureCookieTest extends TestCase
{
    public function testConstructorWithDefaults(): void
    {
        $cookie = new SecureCookie('session', 'abc123');

        $this->assertSame('session', $cookie->name);
        $this->assertSame('abc123', $cookie->value);
        $this->assertTrue($cookie->options->secure);
        $this->assertTrue($cookie->options->httpOnly);
    }

    public function testConstructorWithCustomOptions(): void
    {
        $options = CookieOptions::lax();
        $cookie  = new SecureCookie('pref', 'value', $options);

        $this->assertSame('pref', $cookie->name);
        $this->assertSame('value', $cookie->value);
        $this->assertSame(SameSitePolicy::LAX, $cookie->options->sameSite);
    }

    public function testConstructorRejectsInvalidName(): void
    {
        $this->expectException(InvalidCookieNameException::class);

        new SecureCookie('invalid;name', 'value');
    }

    public function testConstructorValidatesHostPrefixConstraints(): void
    {
        // __Host- prefix requires: Secure=true, Path=/, Domain must be empty
        // Using a non-empty domain should fail
        $this->expectException(InvalidCookieNameException::class);
        $this->expectExceptionMessage('__Host-');

        new SecureCookie('__Host-session', 'value', new CookieOptions(domain: 'example.com'));
    }

    public function testConstructorValidatesSecurePrefixConstraints(): void
    {
        // __Secure- prefix requires: Secure=true
        // Using secure=false should fail
        $this->expectException(InvalidCookieNameException::class);
        $this->expectExceptionMessage('__Secure-');

        new SecureCookie('__Secure-token', 'value', CookieOptions::development());
    }

    public function testConstructorRejectsEmptyName(): void
    {
        $this->expectException(InvalidCookieNameException::class);

        new SecureCookie('', 'value');
    }

    public function testConstructorRejectsInvalidValue(): void
    {
        $this->expectException(InvalidCookieValueException::class);

        new SecureCookie('name', "value\ninjection");
    }

    public function testWithValue(): void
    {
        $cookie    = new SecureCookie('name', 'original');
        $newCookie = $cookie->withValue('updated');

        $this->assertSame('original', $cookie->value);
        $this->assertSame('updated', $newCookie->value);
        $this->assertNotSame($cookie, $newCookie);
    }

    public function testWithValueRejectsInvalid(): void
    {
        $cookie = new SecureCookie('name', 'value');

        $this->expectException(InvalidCookieValueException::class);
        $cookie->withValue("invalid;value");
    }

    public function testWithOptions(): void
    {
        $cookie    = new SecureCookie('name', 'value');
        $newCookie = $cookie->withOptions(CookieOptions::development());

        $this->assertTrue($cookie->options->secure);
        $this->assertFalse($newCookie->options->secure);
        $this->assertNotSame($cookie, $newCookie);
    }

    public function testWithMaxAge(): void
    {
        $cookie    = new SecureCookie('name', 'value');
        $now       = time();
        $newCookie = $cookie->withMaxAge(3600);

        $this->assertSame(0, $cookie->options->expires);
        $this->assertGreaterThanOrEqual($now + 3600, $newCookie->options->expires);
    }

    public function testWithPath(): void
    {
        $cookie    = new SecureCookie('name', 'value');
        $newCookie = $cookie->withPath('/admin');

        $this->assertSame('/', $cookie->options->path);
        $this->assertSame('/admin', $newCookie->options->path);
    }

    public function testWithDomain(): void
    {
        $cookie    = new SecureCookie('name', 'value');
        $newCookie = $cookie->withDomain('example.com');

        $this->assertSame('', $cookie->options->domain);
        $this->assertSame('example.com', $newCookie->options->domain);
    }

    public function testHeaderValue(): void
    {
        $cookie = new SecureCookie('session', 'abc123');
        $header = $cookie->headerValue();

        $this->assertStringContainsString('session=abc123', $header);
        $this->assertStringContainsString('Path=/', $header);
        $this->assertStringContainsString('Secure', $header);
        $this->assertStringContainsString('HttpOnly', $header);
        $this->assertStringContainsString('SameSite=Strict', $header);
    }

    public function testHeaderValueWithExpires(): void
    {
        $expires = time() + 3600;
        $cookie  = new SecureCookie('name', 'value', new CookieOptions(expires: $expires));
        $header  = $cookie->headerValue();

        $this->assertStringContainsString('Expires=', $header);
        $this->assertStringContainsString('Max-Age=', $header);
    }

    public function testHeaderValueWithDomain(): void
    {
        $cookie = new SecureCookie('name', 'value', new CookieOptions(domain: 'example.com'));
        $header = $cookie->headerValue();

        $this->assertStringContainsString('Domain=example.com', $header);
    }

    public function testHeaderValueWithoutSecure(): void
    {
        $cookie = new SecureCookie('name', 'value', CookieOptions::development());
        $header = $cookie->headerValue();

        $this->assertStringNotContainsString('; Secure;', $header);
        $this->assertStringNotContainsString('; Secure', $header);
    }

    public function testToDelete(): void
    {
        $cookie       = new SecureCookie('session', 'abc123');
        $deleteCookie = $cookie->toDelete();

        $this->assertSame('session', $deleteCookie->name);
        $this->assertSame('', $deleteCookie->value);
        $this->assertSame(1, $deleteCookie->options->expires);
    }

    public function testSessionFactory(): void
    {
        $cookie = SecureCookie::session('SESSID', 'token123');

        $this->assertSame('SESSID', $cookie->name);
        $this->assertSame('token123', $cookie->value);
        $this->assertTrue($cookie->options->secure);
        $this->assertTrue($cookie->options->httpOnly);
        $this->assertSame(SameSitePolicy::STRICT, $cookie->options->sameSite);
    }

    public function testPersistentFactory(): void
    {
        $now    = time();
        $cookie = SecureCookie::persistent('remember', 'token', 86400);

        $this->assertSame('remember', $cookie->name);
        $this->assertSame('token', $cookie->value);
        $this->assertGreaterThanOrEqual($now + 86400, $cookie->options->expires);
    }

    public function testCookieValueWithSpacesIsInvalid(): void
    {
        // RFC 6265: Cookie values cannot contain spaces (must be URL-encoded by the application)
        $this->expectException(InvalidCookieValueException::class);

        new SecureCookie('name', 'value with spaces');
    }

    public function testCookieValueWithSpecialCharacters(): void
    {
        // Valid cookie value characters (alphanumeric)
        $cookie = new SecureCookie('name', 'abc123XYZ');
        $header = $cookie->headerValue();

        $this->assertStringContainsString('name=abc123XYZ', $header);
    }

    public function testImmutability(): void
    {
        $original = new SecureCookie('name', 'value');

        $original->withValue('new');
        $original->withOptions(CookieOptions::development());
        $original->withMaxAge(3600);
        $original->withPath('/test');
        $original->withDomain('example.com');

        $this->assertSame('value', $original->value);
        $this->assertSame('/', $original->options->path);
        $this->assertSame('', $original->options->domain);
        $this->assertTrue($original->options->secure);
    }

    /**
     * Test send() method behavior.
     *
     * NOTE: SecureCookie::send() relies on PHP's setcookie() function.
     * In CLI/test environments, the behavior depends on PHP version and SAPI:
     * - setcookie() may return true even in CLI (no actual headers sent)
     * - headers_sent() behavior varies by PHP configuration
     *
     * To properly test actual cookie sending:
     * - Use integration tests with a real HTTP server
     * - Use process isolation with PHPUnit (@runInSeparateProcess)
     * - Use a mock wrapper around setcookie() (requires code changes)
     *
     * This test verifies send() returns a boolean and can be called.
     */
    public function testSendReturnsBoolean(): void
    {
        $cookie = new SecureCookie('session', 'value123');
        $result = $cookie->send();

        $this->assertIsBool($result);
    }

    /**
     * Verify that send() validates cookie before attempting to send.
     *
     * The validation in the constructor ensures invalid cookies are rejected early,
     * before send() is ever called.
     */
    public function testSendValidatesBeforeSending(): void
    {
        // Valid cookie can be created and send() called
        $validCookie = new SecureCookie('valid', 'value');
        $this->assertIsBool($validCookie->send());

        // Invalid cookie cannot even be created
        $this->expectException(InvalidCookieNameException::class);
        new SecureCookie('invalid;name', 'value');
    }
}
