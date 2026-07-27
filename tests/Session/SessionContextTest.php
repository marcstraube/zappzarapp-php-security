<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Session;

use Override;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Session\SessionContext;

#[CoversClass(SessionContext::class)]
final class SessionContextTest extends TestCase
{
    /**
     * @var array<string, mixed>
     */
    private array $serverBackup = [];

    #[Override]
    protected function setUp(): void
    {
        $this->serverBackup = $_SERVER;
    }

    #[Override]
    protected function tearDown(): void
    {
        $_SERVER = $this->serverBackup;
    }

    #[Test]
    public function testDefaultsToEmptyAttributes(): void
    {
        $context = new SessionContext();

        $this->assertSame('', $context->ipAddress);
        $this->assertSame('', $context->userAgent);
    }

    #[Test]
    public function testHoldsExplicitAttributes(): void
    {
        $context = new SessionContext('192.0.2.10', 'ExampleBrowser/1.0');

        $this->assertSame('192.0.2.10', $context->ipAddress);
        $this->assertSame('ExampleBrowser/1.0', $context->userAgent);
    }

    #[Test]
    public function testFromGlobalsReadsServerVariables(): void
    {
        $_SERVER['REMOTE_ADDR']     = '192.0.2.10';
        $_SERVER['HTTP_USER_AGENT'] = 'ExampleBrowser/1.0';

        $context = SessionContext::fromGlobals();

        $this->assertSame('192.0.2.10', $context->ipAddress);
        $this->assertSame('ExampleBrowser/1.0', $context->userAgent);
    }

    #[Test]
    public function testFromGlobalsDefaultsToEmptyStrings(): void
    {
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);

        $context = SessionContext::fromGlobals();

        $this->assertSame('', $context->ipAddress);
        $this->assertSame('', $context->userAgent);
    }

    #[Test]
    public function testFromGlobalsIgnoresNonStringValues(): void
    {
        $_SERVER['REMOTE_ADDR']     = 42;
        $_SERVER['HTTP_USER_AGENT'] = ['array'];

        $context = SessionContext::fromGlobals();

        $this->assertSame('', $context->ipAddress);
        $this->assertSame('', $context->userAgent);
    }
}
