<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Session\SessionConfig;
use Zappzarapp\Security\Session\SessionContext;
use Zappzarapp\Security\Session\SessionFingerprint;

#[CoversClass(SessionFingerprint::class)]
#[UsesClass(SessionConfig::class)]
#[UsesClass(SessionContext::class)]
final class SessionFingerprintTest extends TestCase
{
    #[Test]
    public function testComputesDeterministicSha256Hex(): void
    {
        $fingerprint = new SessionFingerprint(new SessionConfig());
        $context     = new SessionContext('192.0.2.10', 'ExampleBrowser/1.0');

        $first  = $fingerprint->compute($context);
        $second = $fingerprint->compute($context);

        $this->assertSame($first, $second);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}\z/', $first);
    }

    #[Test]
    public function testMatchesKnownAnswer(): void
    {
        $fingerprint = new SessionFingerprint(new SessionConfig(bindIpAddress: true));

        $expected = hash(
            'sha256',
            "zappzarapp-session-fingerprint-v1\x00ip:192.0.2.10\x00ua:ExampleBrowser/1.0"
        );

        $this->assertSame(
            $expected,
            $fingerprint->compute(new SessionContext('192.0.2.10', 'ExampleBrowser/1.0'))
        );
    }

    #[Test]
    public function testChangesWithUserAgentWhenBound(): void
    {
        $fingerprint = new SessionFingerprint(new SessionConfig(bindUserAgent: true));

        $this->assertNotSame(
            $fingerprint->compute(new SessionContext('192.0.2.10', 'BrowserA/1.0')),
            $fingerprint->compute(new SessionContext('192.0.2.10', 'BrowserB/2.0'))
        );
    }

    #[Test]
    public function testIgnoresUserAgentWhenNotBound(): void
    {
        $fingerprint = new SessionFingerprint(new SessionConfig(bindUserAgent: false));

        $this->assertSame(
            $fingerprint->compute(new SessionContext('192.0.2.10', 'BrowserA/1.0')),
            $fingerprint->compute(new SessionContext('192.0.2.10', 'BrowserB/2.0'))
        );
    }

    #[Test]
    public function testIgnoresIpAddressByDefault(): void
    {
        $fingerprint = new SessionFingerprint(new SessionConfig());

        $this->assertSame(
            $fingerprint->compute(new SessionContext('192.0.2.10', 'ExampleBrowser/1.0')),
            $fingerprint->compute(new SessionContext('198.51.100.7', 'ExampleBrowser/1.0'))
        );
    }

    #[Test]
    public function testChangesWithIpAddressWhenBound(): void
    {
        $fingerprint = new SessionFingerprint(new SessionConfig(bindIpAddress: true));

        $this->assertNotSame(
            $fingerprint->compute(new SessionContext('192.0.2.10', 'ExampleBrowser/1.0')),
            $fingerprint->compute(new SessionContext('198.51.100.7', 'ExampleBrowser/1.0'))
        );
    }

    #[Test]
    public function testBindingConfigurationsProduceDistinctFingerprints(): void
    {
        $context = new SessionContext('192.0.2.10', 'ExampleBrowser/1.0');

        $userAgentOnly = new SessionFingerprint(new SessionConfig());
        $ipOnly        = new SessionFingerprint(new SessionConfig(bindUserAgent: false, bindIpAddress: true));
        $both          = new SessionFingerprint(new SessionConfig(bindIpAddress: true));

        $this->assertNotSame($userAgentOnly->compute($context), $ipOnly->compute($context));
        $this->assertNotSame($userAgentOnly->compute($context), $both->compute($context));
        $this->assertNotSame($ipOnly->compute($context), $both->compute($context));
    }
}
