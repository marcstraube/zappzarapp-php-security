<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Cookie;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cookie\CookieOptions;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieOptionsException;
use Zappzarapp\Security\Cookie\SameSitePolicy;

#[CoversClass(CookieOptions::class)]
#[UsesClass(InvalidCookieOptionsException::class)]
#[UsesClass(SameSitePolicy::class)]
final class CookieOptionsTest extends TestCase
{
    #[Test]
    public function testDefaultValuesAreSecure(): void
    {
        $options = new CookieOptions();

        $this->assertSame(0, $options->expires);
        $this->assertSame('/', $options->path);
        $this->assertSame('', $options->domain);
        $this->assertTrue($options->secure);
        $this->assertTrue($options->httpOnly);
        $this->assertSame(SameSitePolicy::STRICT, $options->sameSite);
    }

    #[Test]
    public function testWithExpires(): void
    {
        $options    = new CookieOptions();
        $timestamp  = time() + 3600;
        $newOptions = $options->withExpires($timestamp);

        $this->assertSame(0, $options->expires);
        $this->assertSame($timestamp, $newOptions->expires);
        $this->assertNotSame($options, $newOptions);
    }

    #[Test]
    public function testWithMaxAge(): void
    {
        $options    = new CookieOptions();
        $now        = time();
        $newOptions = $options->withMaxAge(3600);

        $this->assertSame(0, $options->expires);
        $this->assertGreaterThanOrEqual($now + 3600, $newOptions->expires);
        $this->assertLessThanOrEqual($now + 3601, $newOptions->expires);
    }

    #[Test]
    public function testWithPath(): void
    {
        $options    = new CookieOptions();
        $newOptions = $options->withPath('/admin');

        $this->assertSame('/', $options->path);
        $this->assertSame('/admin', $newOptions->path);
        $this->assertNotSame($options, $newOptions);
    }

    #[Test]
    public function testWithDomain(): void
    {
        $options    = new CookieOptions();
        $newOptions = $options->withDomain('example.com');

        $this->assertSame('', $options->domain);
        $this->assertSame('example.com', $newOptions->domain);
        $this->assertNotSame($options, $newOptions);
    }

    #[Test]
    public function testWithSecure(): void
    {
        $options    = new CookieOptions(secure: false);
        $newOptions = $options->withSecure();

        $this->assertFalse($options->secure);
        $this->assertTrue($newOptions->secure);
        $this->assertNotSame($options, $newOptions);
    }

    #[Test]
    public function testWithoutSecure(): void
    {
        $options    = new CookieOptions();
        $newOptions = $options->withoutSecure();

        $this->assertTrue($options->secure);
        $this->assertFalse($newOptions->secure);
        $this->assertNotSame($options, $newOptions);
    }

    #[Test]
    public function testWithHttpOnly(): void
    {
        $options    = new CookieOptions(httpOnly: false);
        $newOptions = $options->withHttpOnly();

        $this->assertFalse($options->httpOnly);
        $this->assertTrue($newOptions->httpOnly);
        $this->assertNotSame($options, $newOptions);
    }

    #[Test]
    public function testWithoutHttpOnly(): void
    {
        $options    = new CookieOptions();
        $newOptions = $options->withoutHttpOnly();

        $this->assertTrue($options->httpOnly);
        $this->assertFalse($newOptions->httpOnly);
        $this->assertNotSame($options, $newOptions);
    }

    #[Test]
    public function testWithSameSite(): void
    {
        $options    = new CookieOptions();
        $newOptions = $options->withSameSite(SameSitePolicy::LAX);

        $this->assertSame(SameSitePolicy::STRICT, $options->sameSite);
        $this->assertSame(SameSitePolicy::LAX, $newOptions->sameSite);
        $this->assertNotSame($options, $newOptions);
    }

    #[Test]
    public function testToArray(): void
    {
        $options = new CookieOptions(
            expires: 1234567890,
            path: '/test',
            domain: 'example.com',
            secure: true,
            httpOnly: true,
            sameSite: SameSitePolicy::LAX
        );

        $array = $options->toArray();

        $this->assertSame(1234567890, $array['expires']);
        $this->assertSame('/test', $array['path']);
        $this->assertSame('example.com', $array['domain']);
        $this->assertTrue($array['secure']);
        $this->assertTrue($array['httponly']);
        $this->assertSame('Lax', $array['samesite']);
    }

    #[Test]
    public function testStrictFactory(): void
    {
        $options = CookieOptions::strict();

        $this->assertTrue($options->secure);
        $this->assertTrue($options->httpOnly);
        $this->assertSame(SameSitePolicy::STRICT, $options->sameSite);
    }

    #[Test]
    public function testLaxFactory(): void
    {
        $options = CookieOptions::lax();

        $this->assertTrue($options->secure);
        $this->assertTrue($options->httpOnly);
        $this->assertSame(SameSitePolicy::LAX, $options->sameSite);
    }

    #[Test]
    public function testJsAccessibleFactory(): void
    {
        $options = CookieOptions::jsAccessible();

        $this->assertTrue($options->secure);
        $this->assertFalse($options->httpOnly);
        $this->assertSame(SameSitePolicy::STRICT, $options->sameSite);
    }

    #[Test]
    public function testDevelopmentFactory(): void
    {
        $options = CookieOptions::development();

        $this->assertFalse($options->secure);
        $this->assertTrue($options->httpOnly);
        $this->assertSame(SameSitePolicy::LAX, $options->sameSite);
    }

    #[Test]
    public function testImmutability(): void
    {
        $original = new CookieOptions();

        $original->withExpires(time() + 3600);
        $original->withPath('/test');
        $original->withDomain('example.com');
        $original->withoutSecure();
        $original->withoutHttpOnly();
        $original->withSameSite(SameSitePolicy::NONE);

        $this->assertSame(0, $original->expires);
        $this->assertSame('/', $original->path);
        $this->assertSame('', $original->domain);
        $this->assertTrue($original->secure);
        $this->assertTrue($original->httpOnly);
        $this->assertSame(SameSitePolicy::STRICT, $original->sameSite);
    }

    #[Test]
    public function testChainedModifications(): void
    {
        $options = (new CookieOptions())
            ->withExpires(1234567890)
            ->withPath('/admin')
            ->withDomain('example.com')
            ->withoutHttpOnly()
            ->withSameSiteNone(); // Uses withSameSiteNone() which auto-enables secure

        $this->assertSame(1234567890, $options->expires);
        $this->assertSame('/admin', $options->path);
        $this->assertSame('example.com', $options->domain);
        $this->assertTrue($options->secure); // SameSite=None requires Secure
        $this->assertFalse($options->httpOnly);
        $this->assertSame(SameSitePolicy::NONE, $options->sameSite);
    }

    #[Test]
    public function testWithSameSiteNoneThrowsWithoutSecure(): void
    {
        $options = (new CookieOptions())->withoutSecure();

        $this->expectException(InvalidCookieOptionsException::class);
        $this->expectExceptionMessage('SameSite=None requires Secure flag');

        $options->withSameSite(SameSitePolicy::NONE);
    }

    #[Test]
    public function testWithSameSiteNoneAutoEnablesSecure(): void
    {
        $options = (new CookieOptions())
            ->withoutSecure()
            ->withSameSiteNone();

        $this->assertTrue($options->secure);
        $this->assertSame(SameSitePolicy::NONE, $options->sameSite);
    }

    #[DataProvider('invalidDomainProvider')]
    #[Test]
    public function testWithDomainRejectsHeaderInjectionCharacters(string $invalidDomain): void
    {
        $options = new CookieOptions();

        $this->expectException(InvalidCookieOptionsException::class);
        $this->expectExceptionMessage('contains invalid characters');

        $options->withDomain($invalidDomain);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidDomainProvider(): array
    {
        return [
            'carriage return' => ["example.com\rSet-Cookie: evil=value"],
            'newline'         => ["example.com\nSet-Cookie: evil=value"],
            'semicolon'       => ['example.com; path=/; httponly'],
            'comma'           => ['example.com, evil.com'],
            'crlf injection'  => ["example.com\r\nSet-Cookie: stolen=session"],
        ];
    }

    #[DataProvider('invalidPathProvider')]
    #[Test]
    public function testWithPathRejectsHeaderInjectionCharacters(string $invalidPath): void
    {
        $options = new CookieOptions();

        $this->expectException(InvalidCookieOptionsException::class);
        $this->expectExceptionMessage('contains invalid characters');

        $options->withPath($invalidPath);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidPathProvider(): array
    {
        return [
            'carriage return' => ["/admin\rSet-Cookie: evil=value"],
            'newline'         => ["/admin\nSet-Cookie: evil=value"],
            'semicolon'       => ['/admin; domain=evil.com'],
            'comma'           => ['/path1, /path2'],
        ];
    }
}
