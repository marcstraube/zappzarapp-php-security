<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Session;

use Override;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cookie\SameSitePolicy;
use Zappzarapp\Security\Session\Exception\SessionConfigurationException;
use Zappzarapp\Security\Session\SessionConfig;
use Zappzarapp\Security\Session\SessionConfigurator;

#[CoversClass(SessionConfigurator::class)]
#[CoversClass(SessionConfigurationException::class)]
#[UsesClass(SessionConfig::class)]
final class SessionConfiguratorTest extends TestCase
{
    /**
     * @var array<string, string>
     */
    private array $iniBackup = [];

    private string $sessionNameBackup = '';

    /**
     * @var array{lifetime: int, path: string, domain: string, secure: bool, httponly: bool, samesite: string}
     */
    private array $cookieParamsBackup;

    #[Override]
    protected function setUp(): void
    {
        $this->sessionNameBackup   = (string) session_name();
        $this->cookieParamsBackup  = session_get_cookie_params();

        foreach ([
            'session.use_strict_mode',
            'session.cache_limiter',
            'session.gc_maxlifetime',
        ] as $key) {
            $this->iniBackup[$key] = (string) ini_get($key);
        }
    }

    #[Override]
    protected function tearDown(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_unset();
            session_destroy();
        }

        session_id('');
        session_name($this->sessionNameBackup);

        $samesite = $this->cookieParamsBackup['samesite'];
        session_set_cookie_params([
            'lifetime' => $this->cookieParamsBackup['lifetime'],
            'path'     => $this->cookieParamsBackup['path'],
            'domain'   => $this->cookieParamsBackup['domain'],
            'secure'   => $this->cookieParamsBackup['secure'],
            'httponly' => $this->cookieParamsBackup['httponly'],
            'samesite' => in_array($samesite, ['Lax', 'lax', 'None', 'none', 'Strict', 'strict'], true)
                ? $samesite
                : 'Lax',
        ]);

        foreach ($this->iniBackup as $key => $value) {
            ini_set($key, $value);
        }
    }

    #[Test]
    public function testConfigureAppliesHardenedSettings(): void
    {
        // Start from deliberately insecure values so the assertions prove
        // the configurator actively sets them (not just inherits defaults)
        ini_set('session.use_strict_mode', '0');
        ini_set('session.cache_limiter', 'public');
        ini_set('session.gc_maxlifetime', '1');

        (new SessionConfigurator())->configure(new SessionConfig());

        $this->assertSame('1', ini_get('session.use_strict_mode'));
        $this->assertSame('nocache', ini_get('session.cache_limiter'));
        $this->assertSame('1800', ini_get('session.gc_maxlifetime'));
    }

    #[Test]
    public function testConfigureSetsSessionName(): void
    {
        (new SessionConfigurator())->configure(new SessionConfig());

        $this->assertSame('__Host-session', session_name());
    }

    #[Test]
    public function testConfigureSetsSecureCookieParams(): void
    {
        // Start from non-default params so every array item is proven to be set
        session_set_cookie_params([
            'lifetime' => 999,
            'path'     => '/old',
            'domain'   => 'old.example',
            'secure'   => false,
            'httponly' => false,
            'samesite' => 'Strict',
        ]);

        (new SessionConfigurator())->configure(new SessionConfig());

        $this->assertSame(
            [
                'lifetime' => 0,
                'path'     => '/',
                'domain'   => '',
                'secure'   => true,
                'httponly' => true,
                'samesite' => 'Lax',
            ],
            session_get_cookie_params()
        );
    }

    #[Test]
    public function testConfigureRespectsCustomConfig(): void
    {
        $config = new SessionConfig(
            idleTimeout: 900,
            secureCookie: false,
            sameSite: SameSitePolicy::STRICT,
            cookieName: 'app_session',
        );

        (new SessionConfigurator())->configure($config);

        $params = session_get_cookie_params();

        $this->assertSame('app_session', session_name());
        $this->assertSame('900', ini_get('session.gc_maxlifetime'));
        $this->assertFalse($params['secure']);
        $this->assertSame('Strict', $params['samesite']);
    }

    #[Test]
    public function testConfigureThrowsWhenSessionIsActive(): void
    {
        session_id('test' . bin2hex(random_bytes(8)));
        session_start();

        $this->expectException(SessionConfigurationException::class);
        $this->expectExceptionMessage('a session is already active');

        (new SessionConfigurator())->configure(new SessionConfig());
    }
}
