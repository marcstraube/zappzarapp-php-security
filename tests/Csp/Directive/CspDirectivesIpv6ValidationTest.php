<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Directive;

use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;

/**
 * Tests for CspDirectives IPv6 WebSocket host validation
 */
final class CspDirectivesIpv6ValidationTest extends TestCase
{
    public function testAcceptsValidWebSocketHostWithIpv6Localhost(): void
    {
        $directives = new CspDirectives(websocketHost: '[::1]:8080');

        $this->assertSame('[::1]:8080', $directives->websocketHost);
    }

    public function testAcceptsValidWebSocketHostWithIpv6Full(): void
    {
        $directives = new CspDirectives(websocketHost: '[2001:db8::1]:443');

        $this->assertSame('[2001:db8::1]:443', $directives->websocketHost);
    }

    public function testAcceptsValidWebSocketHostWithIpv6AllZeros(): void
    {
        $directives = new CspDirectives(websocketHost: '[::]:9000');

        $this->assertSame('[::]:9000', $directives->websocketHost);
    }

    public function testAcceptsValidWebSocketHostWithIpv4MappedIpv6(): void
    {
        $directives = new CspDirectives(websocketHost: '[::ffff:192.168.1.1]:8080');

        $this->assertSame('[::ffff:192.168.1.1]:8080', $directives->websocketHost);
    }

    public function testAcceptsValidWebSocketHostWithIpv4MappedIpv6Localhost(): void
    {
        $directives = new CspDirectives(websocketHost: '[::ffff:127.0.0.1]:5173');

        $this->assertSame('[::ffff:127.0.0.1]:5173', $directives->websocketHost);
    }

    public function testThrowsForIpv6WithoutBrackets(): void
    {
        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('WebSocket host format is invalid');

        new CspDirectives(websocketHost: '::1:8080');
    }
}
