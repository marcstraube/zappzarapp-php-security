<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Uri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Uri\NativeDnsResolver;

#[CoversClass(NativeDnsResolver::class)]
final class NativeDnsResolverTest extends TestCase
{
    private NativeDnsResolver $resolver;

    protected function setUp(): void
    {
        $this->resolver = new NativeDnsResolver();
    }

    public function testResolveLocalhostReturnsLoopback(): void
    {
        $ips = $this->resolver->resolve('localhost');

        $this->assertContains('127.0.0.1', $ips);
    }

    public function testResolveNonExistentHostReturnsEmptyArray(): void
    {
        $ips = $this->resolver->resolve('this-host-definitely-does-not-exist-xyz123.invalid');

        $this->assertSame([], $ips);
    }

    public function testResolveReturnsUniqueIps(): void
    {
        // dns.google is a well-known public hostname with stable DNS
        $ips = $this->resolver->resolve('dns.google');

        // The result should contain unique values only
        $this->assertSame($ips, array_values(array_unique($ips)));
    }

    public function testResolveReturnsListOfStrings(): void
    {
        $ips = $this->resolver->resolve('localhost');

        $this->assertIsList($ips);

        foreach ($ips as $ip) {
            $this->assertIsString($ip);
        }
    }

    // =========================================================================
    // Tests for dns_get_record path using testable subclass
    // =========================================================================

    public function testResolveUsesGethostbynameResult(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): string
            {
                return '1.2.3.4';
            }

            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [];
            }
        };

        $ips = $resolver->resolve('example.com');

        $this->assertSame(['1.2.3.4'], $ips);
    }

    public function testResolveUsesDnsGetRecordIpv4Results(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): ?string
            {
                return null;
            }

            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [
                    ['ip' => '5.6.7.8'],
                    ['ip' => '9.10.11.12'],
                ];
            }
        };

        $ips = $resolver->resolve('example.com');

        $this->assertSame(['5.6.7.8', '9.10.11.12'], $ips);
    }

    public function testResolveUsesDnsGetRecordIpv6Results(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): ?string
            {
                return null;
            }

            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [
                    ['ipv6' => '2001:4860:4860::8888'],
                    ['ipv6' => '2001:4860:4860::8844'],
                ];
            }
        };

        $ips = $resolver->resolve('example.com');

        $this->assertSame(['2001:4860:4860::8888', '2001:4860:4860::8844'], $ips);
    }

    public function testResolveCombinesBothResolutionMethods(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): string
            {
                return '1.2.3.4';
            }

            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [
                    ['ip' => '5.6.7.8'],
                    ['ipv6' => '2001:db8::1'],
                ];
            }
        };

        $ips = $resolver->resolve('example.com');

        $this->assertSame(['1.2.3.4', '5.6.7.8', '2001:db8::1'], $ips);
    }

    public function testResolveDeduplicatesResults(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): string
            {
                return '1.2.3.4';
            }

            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [
                    ['ip' => '1.2.3.4'],
                    ['ip' => '5.6.7.8'],
                ];
            }
        };

        $ips = $resolver->resolve('example.com');

        $this->assertSame(['1.2.3.4', '5.6.7.8'], $ips);
    }

    public function testResolveSkipsRecordsWithNonStringIp(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): ?string
            {
                return null;
            }

            /**
             * @return list<array<string, mixed>>
             */
            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [
                    ['ip' => 12345],
                    ['ip' => '5.6.7.8'],
                ];
            }
        };

        $ips = $resolver->resolve('example.com');

        $this->assertSame(['5.6.7.8'], $ips);
    }

    public function testResolveSkipsRecordsWithNonStringIpv6(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): ?string
            {
                return null;
            }

            /**
             * @return list<array<string, mixed>>
             */
            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [
                    ['ipv6' => null],
                    ['ipv6' => '2001:db8::1'],
                ];
            }
        };

        $ips = $resolver->resolve('example.com');

        $this->assertSame(['2001:db8::1'], $ips);
    }

    public function testResolveSkipsRecordsWithoutIpFields(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): ?string
            {
                return null;
            }

            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [
                    ['type' => 'TXT', 'txt' => 'some text'],
                    ['ip' => '5.6.7.8'],
                ];
            }
        };

        $ips = $resolver->resolve('example.com');

        $this->assertSame(['5.6.7.8'], $ips);
    }

    public function testResolveHandlesEmptyDnsGetRecordResult(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): string
            {
                return '1.2.3.4';
            }

            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [];
            }
        };

        $ips = $resolver->resolve('example.com');

        $this->assertSame(['1.2.3.4'], $ips);
    }

    public function testResolveHandlesMixedRecordTypes(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): ?string
            {
                return null;
            }

            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [
                    ['ip' => '1.2.3.4', 'ipv6' => '2001:db8::1'],
                    ['ip'   => '5.6.7.8'],
                    ['ipv6' => '2001:db8::2'],
                ];
            }
        };

        $ips = $resolver->resolve('example.com');

        $this->assertSame(['1.2.3.4', '2001:db8::1', '5.6.7.8', '2001:db8::2'], $ips);
    }

    public function testResolveReturnsEmptyWhenBothMethodsFail(): void
    {
        $resolver = new class extends NativeDnsResolver {
            protected function resolveViaGethostbyname(string $host): ?string
            {
                return null;
            }

            protected function resolveViaDnsGetRecord(string $host): array
            {
                return [];
            }
        };

        $ips = $resolver->resolve('nonexistent.invalid');

        $this->assertSame([], $ips);
    }
}
