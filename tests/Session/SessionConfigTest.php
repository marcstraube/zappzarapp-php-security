<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cookie\SameSitePolicy;
use Zappzarapp\Security\Session\Exception\SessionConfigurationException;
use Zappzarapp\Security\Session\SessionConfig;

#[CoversClass(SessionConfig::class)]
#[CoversClass(SessionConfigurationException::class)]
final class SessionConfigTest extends TestCase
{
    #[Test]
    public function testSecureDefaults(): void
    {
        $config = new SessionConfig();

        $this->assertSame(1800, $config->idleTimeout);
        $this->assertSame(43200, $config->absoluteTimeout);
        $this->assertTrue($config->bindUserAgent);
        $this->assertFalse($config->bindIpAddress);
        $this->assertTrue($config->secureCookie);
        $this->assertSame(SameSitePolicy::LAX, $config->sameSite);
        $this->assertSame('__Host-session', $config->cookieName);
    }

    #[Test]
    public function testStrictFactory(): void
    {
        $config = SessionConfig::strict();

        $this->assertSame(900, $config->idleTimeout);
        $this->assertSame(14400, $config->absoluteTimeout);
        $this->assertTrue($config->bindUserAgent);
        $this->assertTrue($config->bindIpAddress);
        $this->assertTrue($config->secureCookie);
        $this->assertSame(SameSitePolicy::STRICT, $config->sameSite);
    }

    #[Test]
    public function testRejectsNonPositiveIdleTimeout(): void
    {
        $this->expectException(SessionConfigurationException::class);
        $this->expectExceptionMessage('Session idle timeout must be a positive number of seconds, got 0');

        new SessionConfig(idleTimeout: 0);
    }

    #[Test]
    public function testRejectsNonPositiveAbsoluteTimeout(): void
    {
        $this->expectException(SessionConfigurationException::class);
        $this->expectExceptionMessage('Session absolute timeout must be a positive number of seconds, got -1');

        new SessionConfig(absoluteTimeout: -1);
    }

    #[Test]
    public function testRejectsIdleTimeoutExceedingAbsoluteTimeout(): void
    {
        $this->expectException(SessionConfigurationException::class);
        $this->expectExceptionMessage('Session idle timeout (3601) must not exceed the absolute timeout (3600)');

        new SessionConfig(idleTimeout: 3601, absoluteTimeout: 3600);
    }

    #[Test]
    public function testAcceptsEqualIdleAndAbsoluteTimeout(): void
    {
        $config = new SessionConfig(idleTimeout: 3600, absoluteTimeout: 3600);

        $this->assertSame(3600, $config->idleTimeout);
        $this->assertSame(3600, $config->absoluteTimeout);
    }

    #[Test]
    public function testAcceptsMinimalTimeouts(): void
    {
        $config = new SessionConfig(idleTimeout: 1, absoluteTimeout: 1);

        $this->assertSame(1, $config->idleTimeout);
    }

    #[DataProvider('invalidCookieNameProvider')]
    #[Test]
    public function testRejectsInvalidCookieName(string $cookieName): void
    {
        $this->expectException(SessionConfigurationException::class);
        $this->expectExceptionMessage('Session cookie name contains invalid characters');

        new SessionConfig(cookieName: $cookieName);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidCookieNameProvider(): array
    {
        return [
            'empty'            => [''],
            'space'            => ['session id'],
            'semicolon'        => ['session;id'],
            'equals sign'      => ['session=id'],
            'newline'          => ["session\nid"],
            'trailing newline' => ["session\n"],
            'non-ascii'        => ['sessión'],
        ];
    }

    #[Test]
    public function testAcceptsCustomCookieName(): void
    {
        $config = new SessionConfig(cookieName: 'app_session.v2-x');

        $this->assertSame('app_session.v2-x', $config->cookieName);
    }
}
