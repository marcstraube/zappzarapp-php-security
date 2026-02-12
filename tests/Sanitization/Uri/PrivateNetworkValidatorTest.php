<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Uri;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Zappzarapp\Security\Sanitization\Uri\DnsResolver;
use Zappzarapp\Security\Sanitization\Uri\NativeDnsResolver;
use Zappzarapp\Security\Sanitization\Uri\PrivateNetworkValidator;

#[CoversClass(PrivateNetworkValidator::class)]
final class PrivateNetworkValidatorTest extends TestCase
{
    private PrivateNetworkValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new PrivateNetworkValidator();
    }

    // =========================================================================
    // Empty/Invalid Input
    // =========================================================================

    public function testEmptyHostIsBlocked(): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved(''));
    }

    public function testWhitespaceOnlyHostIsBlocked(): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved('   '));
    }

    // =========================================================================
    // IPv4 Loopback Addresses (127.0.0.0/8)
    // =========================================================================

    #[DataProvider('ipv4LoopbackProvider')]
    public function testIpv4LoopbackIsBlocked(string $ip): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ipv4LoopbackProvider(): iterable
    {
        yield 'localhost ip' => ['127.0.0.1'];
        yield 'loopback start' => ['127.0.0.0'];
        yield 'loopback end' => ['127.255.255.255'];
        yield 'loopback middle' => ['127.1.2.3'];
    }

    // =========================================================================
    // IPv4 Private Ranges (RFC 1918)
    // =========================================================================

    #[DataProvider('ipv4PrivateRangeProvider')]
    public function testIpv4PrivateRangesAreBlocked(string $ip): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ipv4PrivateRangeProvider(): iterable
    {
        // 10.0.0.0/8
        yield '10.0.0.0 start' => ['10.0.0.0'];
        yield '10.0.0.1' => ['10.0.0.1'];
        yield '10.255.255.255 end' => ['10.255.255.255'];
        yield '10.128.64.32' => ['10.128.64.32'];

        // 172.16.0.0/12
        yield '172.16.0.0 start' => ['172.16.0.0'];
        yield '172.31.255.255 end' => ['172.31.255.255'];
        yield '172.20.10.5' => ['172.20.10.5'];

        // 192.168.0.0/16
        yield '192.168.0.0 start' => ['192.168.0.0'];
        yield '192.168.255.255 end' => ['192.168.255.255'];
        yield '192.168.1.1' => ['192.168.1.1'];
    }

    // =========================================================================
    // IPv4 Link-Local / Cloud Metadata (169.254.0.0/16)
    // =========================================================================

    #[DataProvider('ipv4LinkLocalProvider')]
    public function testIpv4LinkLocalIsBlocked(string $ip): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ipv4LinkLocalProvider(): iterable
    {
        yield 'link-local start' => ['169.254.0.0'];
        yield 'link-local end' => ['169.254.255.255'];
        yield 'cloud metadata AWS/GCP/Azure' => ['169.254.169.254'];
        yield 'link-local middle' => ['169.254.128.64'];
    }

    // =========================================================================
    // IPv4 Reserved Ranges
    // =========================================================================

    #[DataProvider('ipv4ReservedRangeProvider')]
    public function testIpv4ReservedRangesAreBlocked(string $ip): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ipv4ReservedRangeProvider(): iterable
    {
        yield 'current network 0.0.0.0' => ['0.0.0.0'];
        yield 'current network 0.0.0.1' => ['0.0.0.1'];
        yield 'carrier-grade NAT' => ['100.64.0.1'];
        yield 'IETF protocol' => ['192.0.0.1'];
        yield 'TEST-NET-1' => ['192.0.2.1'];
        yield 'TEST-NET-2' => ['198.51.100.1'];
        yield 'TEST-NET-3' => ['203.0.113.1'];
        yield 'multicast' => ['224.0.0.1'];
        yield 'multicast high' => ['239.255.255.255'];
        yield 'reserved/broadcast' => ['255.255.255.255'];
    }

    // =========================================================================
    // IPv4 Public Addresses (should NOT be blocked)
    // =========================================================================

    #[DataProvider('ipv4PublicProvider')]
    public function testIpv4PublicIsAllowed(string $ip): void
    {
        $this->assertFalse($this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ipv4PublicProvider(): iterable
    {
        yield 'Google DNS' => ['8.8.8.8'];
        yield 'Cloudflare DNS' => ['1.1.1.1'];
        yield 'random public 1' => ['93.184.216.34'];
        yield 'just outside 10.x range' => ['11.0.0.1'];
        yield 'just outside 172.16 range' => ['172.15.255.255'];
        yield 'just outside 172.31 range' => ['172.32.0.0'];
        yield 'just outside 192.168 range' => ['192.167.255.255'];
        yield 'just outside link-local' => ['169.253.255.255'];
    }

    // =========================================================================
    // IPv6 Loopback and Unspecified
    // =========================================================================

    #[DataProvider('ipv6LoopbackProvider')]
    public function testIpv6LoopbackIsBlocked(string $ip): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ipv6LoopbackProvider(): iterable
    {
        yield 'loopback full' => ['0000:0000:0000:0000:0000:0000:0000:0001'];
        yield 'loopback short' => ['::1'];
        yield 'unspecified full' => ['0000:0000:0000:0000:0000:0000:0000:0000'];
        yield 'unspecified short' => ['::'];
    }

    // =========================================================================
    // IPv6 Unique Local (fc00::/7)
    // =========================================================================

    #[DataProvider('ipv6UniqueLocalProvider')]
    public function testIpv6UniqueLocalIsBlocked(string $ip): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ipv6UniqueLocalProvider(): iterable
    {
        yield 'fc00:: start' => ['fc00::1'];
        yield 'fd00:: private' => ['fd00::1'];
        yield 'fdff:: end' => ['fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'];
    }

    // =========================================================================
    // IPv6 Link-Local (fe80::/10)
    // =========================================================================

    #[DataProvider('ipv6LinkLocalProvider')]
    public function testIpv6LinkLocalIsBlocked(string $ip): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ipv6LinkLocalProvider(): iterable
    {
        yield 'fe80:: start' => ['fe80::1'];
        yield 'fe80 with interface' => ['fe80::1:2:3:4'];
        yield 'febf:: end of range' => ['febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff'];
    }

    // =========================================================================
    // IPv6 Public Addresses (should NOT be blocked)
    // =========================================================================

    #[DataProvider('ipv6PublicProvider')]
    public function testIpv6PublicIsAllowed(string $ip): void
    {
        $this->assertFalse($this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function ipv6PublicProvider(): iterable
    {
        yield 'Google DNS' => ['2001:4860:4860::8888'];
        yield 'Cloudflare DNS' => ['2606:4700:4700::1111'];
        yield 'random global' => ['2a00:1450:4001:81f::200e'];
    }

    // =========================================================================
    // IPv6 Bracketed Notation (URI format)
    // =========================================================================

    #[DataProvider('ipv6BracketedProvider')]
    public function testIpv6BracketedNotation(string $ip, bool $shouldBlock): void
    {
        $this->assertSame($shouldBlock, $this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function ipv6BracketedProvider(): iterable
    {
        yield 'bracketed loopback' => ['[::1]', true];
        yield 'bracketed link-local' => ['[fe80::1]', true];
        yield 'bracketed public' => ['[2001:4860:4860::8888]', false];
    }

    // =========================================================================
    // IPv4-Mapped IPv6 Addresses
    // =========================================================================

    #[DataProvider('ipv4MappedIpv6Provider')]
    public function testIpv4MappedIpv6(string $ip, bool $shouldBlock): void
    {
        $this->assertSame($shouldBlock, $this->validator->isPrivateOrReserved($ip));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function ipv4MappedIpv6Provider(): iterable
    {
        yield 'mapped loopback' => ['::ffff:127.0.0.1', true];
        yield 'mapped private 10.x' => ['::ffff:10.0.0.1', true];
        yield 'mapped private 192.168.x' => ['::ffff:192.168.1.1', true];
        yield 'mapped public' => ['::ffff:8.8.8.8', false];
    }

    // =========================================================================
    // Blocked Hostnames
    // =========================================================================

    #[DataProvider('blockedHostnameProvider')]
    public function testBlockedHostnamesAreBlocked(string $hostname): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved($hostname));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function blockedHostnameProvider(): iterable
    {
        yield 'localhost' => ['localhost'];
        yield 'localhost uppercase' => ['LOCALHOST'];
        yield 'localhost.localdomain' => ['localhost.localdomain'];
        yield 'ip6-localhost' => ['ip6-localhost'];
        yield 'ip6-loopback' => ['ip6-loopback'];
        yield 'metadata.google.internal' => ['metadata.google.internal'];
        yield 'kubernetes.default.svc' => ['kubernetes.default.svc'];
        yield 'kubernetes.default' => ['kubernetes.default'];
        yield 'custom .internal domain' => ['my-service.internal'];
        yield 'custom .local domain' => ['printer.local'];
        yield '.internal with trailing dot' => ['service.internal.'];
        yield '.local with trailing dot' => ['device.local.'];
    }

    // =========================================================================
    // Hostname Resolution (real DNS - may be flaky in CI)
    // =========================================================================

    public function testPublicHostnameIsAllowed(): void
    {
        // This test requires actual DNS resolution
        // Using a well-known public hostname
        $this->assertFalse($this->validator->isPrivateOrReserved('dns.google'));
    }

    // =========================================================================
    // Logger Integration
    // =========================================================================

    public function testLoggerIsCalledForBlockedHost(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                'SSRF protection: Blocked request to private/reserved host',
                $this->callback(fn(array $context): bool => $context['host'] === '127.0.0.1'
                    && isset($context['reason']))
            );

        $validator = new PrivateNetworkValidator($logger);
        $validator->isPrivateOrReserved('127.0.0.1');
    }

    public function testLoggerIsNotCalledForAllowedHost(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->never())->method('warning');

        $validator = new PrivateNetworkValidator($logger);
        $validator->isPrivateOrReserved('8.8.8.8');
    }

    public function testLoggerIsCalledForBlockedHostname(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                'SSRF protection: Blocked request to private/reserved host',
                $this->callback(fn(array $context): bool => $context['host'] === 'localhost'
                    && $context['reason'] === 'Blocked hostname')
            );

        $validator = new PrivateNetworkValidator($logger);
        $validator->isPrivateOrReserved('localhost');
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    public function testHostWithLeadingWhitespaceIsTrimmed(): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved('  127.0.0.1'));
    }

    public function testHostWithTrailingWhitespaceIsTrimmed(): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved('127.0.0.1  '));
    }

    public function testHostIsCaseInsensitive(): void
    {
        $this->assertTrue($this->validator->isPrivateOrReserved('LOCALHOST'));
        $this->assertTrue($this->validator->isPrivateOrReserved('LocalHost'));
    }

    public function testInvalidIpv4IsNotTreatedAsIpv4(): void
    {
        // Invalid IPs like "999.999.999.999" fail FILTER_VALIDATE_IP,
        // so they're treated as hostnames and go through DNS resolution.
        // Since the DNS resolution will fail (no such host), they should
        // be allowed (not found in any private range).
        // This is the expected behavior - we don't block on DNS resolution failure.
        $this->assertFalse($this->validator->isPrivateOrReserved('999.999.999.999'));
    }

    // =========================================================================
    // Mutation Testing: strtolower() removal (Line 99)
    // =========================================================================

    #[DataProvider('caseInsensitiveHostnameProvider')]
    public function testHostnameIsCaseInsensitive(string $hostname): void
    {
        // Tests that strtolower() is applied - all variants should be blocked
        $this->assertTrue($this->validator->isPrivateOrReserved($hostname));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function caseInsensitiveHostnameProvider(): iterable
    {
        yield 'LOCALHOST uppercase' => ['LOCALHOST'];
        yield 'LocalHost mixed' => ['LocalHost'];
        yield 'lOcAlHoSt alternating' => ['lOcAlHoSt'];
        yield 'IP6-LOCALHOST uppercase' => ['IP6-LOCALHOST'];
        yield 'Ip6-Loopback mixed' => ['Ip6-Loopback'];
        yield 'METADATA.GOOGLE.INTERNAL uppercase' => ['METADATA.GOOGLE.INTERNAL'];
        yield 'My-Service.Internal mixed' => ['My-Service.Internal'];
        yield 'PRINTER.LOCAL uppercase' => ['PRINTER.LOCAL'];
    }

    // =========================================================================
    // Mutation Testing: logBlocked() removal (Line 116)
    // =========================================================================

    public function testLoggerIsCalledForBlockedIpv6(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                'SSRF protection: Blocked request to private/reserved host',
                $this->callback(fn(array $context): bool => $context['host'] === '::1'
                    && $context['reason'] === 'Private IPv6 address')
            );

        $validator = new PrivateNetworkValidator($logger);
        $validator->isPrivateOrReserved('::1');
    }

    public function testLoggerIsCalledForBlockedBracketedIpv6(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                'SSRF protection: Blocked request to private/reserved host',
                $this->callback(fn(array $context): bool => $context['host'] === '[fe80::1]'
                    && $context['reason'] === 'Private IPv6 address')
            );

        $validator = new PrivateNetworkValidator($logger);
        $validator->isPrivateOrReserved('[fe80::1]');
    }

    // =========================================================================
    // Mutation Testing: return false after IPv6 check (Line 121)
    // =========================================================================

    #[DataProvider('publicIpv6DirectProvider')]
    public function testPublicIpv6ReturnsExactlyFalse(string $ip): void
    {
        // Ensures that public IPv6 addresses return false (not blocked)
        // This kills the mutant that changes "return false" to "return true"
        $result = $this->validator->isPrivateOrReserved($ip);
        $this->assertFalse($result, sprintf('Public IPv6 %s should not be blocked', $ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function publicIpv6DirectProvider(): iterable
    {
        yield 'Google DNS IPv6' => ['2001:4860:4860::8888'];
        yield 'Google DNS IPv6 secondary' => ['2001:4860:4860::8844'];
        yield 'Cloudflare IPv6' => ['2606:4700:4700::1111'];
        yield 'Cloudflare IPv6 secondary' => ['2606:4700:4700::1001'];
        yield 'bracketed Google DNS' => ['[2001:4860:4860::8888]'];
    }

    // =========================================================================
    // Mutation Testing: return false after IPv4 check (Line 132)
    // =========================================================================

    #[DataProvider('publicIpv4DirectProvider')]
    public function testPublicIpv4ReturnsExactlyFalse(string $ip): void
    {
        // Ensures that public IPv4 addresses return false (not blocked)
        // This kills the mutant that changes "return false" to "return true"
        $result = $this->validator->isPrivateOrReserved($ip);
        $this->assertFalse($result, sprintf('Public IPv4 %s should not be blocked', $ip));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function publicIpv4DirectProvider(): iterable
    {
        yield 'Google DNS' => ['8.8.8.8'];
        yield 'Google DNS secondary' => ['8.8.4.4'];
        yield 'Cloudflare DNS' => ['1.1.1.1'];
        yield 'Quad9 DNS' => ['9.9.9.9'];
        yield 'OpenDNS' => ['208.67.222.222'];
    }

    // =========================================================================
    // Mutation Testing: && vs || in bracket check (Line 182)
    // =========================================================================

    #[DataProvider('malformedBracketProvider')]
    public function testMalformedBracketsAreNotStripped(string $input): void
    {
        // If only one bracket is present, the IPv6 extraction should fail
        // and it should not be treated as an IPv6 address
        // These malformed inputs should not be blocked as private IPv6
        // (they will fail validation and be treated as hostnames)
        $result = $this->validator->isPrivateOrReserved($input);

        // Malformed brackets won't match valid IPv6, so they go to DNS resolution
        // which fails, resulting in not-blocked (false)
        $this->assertFalse($result);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedBracketProvider(): iterable
    {
        yield 'opening bracket only' => ['[::1'];
        yield 'closing bracket only' => ['::1]'];
        yield 'opening bracket only fe80' => ['[fe80::1'];
        yield 'closing bracket only fe80' => ['fe80::1]'];
    }

    // =========================================================================
    // Mutation Testing: substr offset -1 vs -2 (Line 183)
    // =========================================================================

    #[DataProvider('correctBracketStrippingProvider')]
    public function testBracketStrippingIsCorrect(string $bracketedIp, bool $shouldBlock): void
    {
        // Ensures that substr($host, 1, -1) correctly strips both brackets
        // A mutant changing -1 to -2 would leave an extra character
        $result = $this->validator->isPrivateOrReserved($bracketedIp);
        $this->assertSame($shouldBlock, $result);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function correctBracketStrippingProvider(): iterable
    {
        // These test that "[::1]" becomes "::1" (not "::1]" or "::") after stripping
        yield 'loopback bracketed' => ['[::1]', true];
        yield 'unspecified bracketed' => ['[::]', true];
        yield 'link-local bracketed' => ['[fe80::1]', true];
        yield 'public bracketed' => ['[2001:4860:4860::8888]', false];
        yield 'unique local bracketed' => ['[fd00::1]', true];
    }

    // =========================================================================
    // Mutation Testing: int cast removal (Line 204)
    // =========================================================================

    #[DataProvider('highValueIpv4Provider')]
    public function testIpv4HighValueAddresses(string $ip, bool $shouldBlock): void
    {
        // Tests IPv4 addresses that, when converted via ip2long(), produce
        // large or negative values depending on signed/unsigned handling.
        // The (int) cast with sprintf('%u', ...) is essential for proper handling.
        $result = $this->validator->isPrivateOrReserved($ip);
        $this->assertSame($shouldBlock, $result);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function highValueIpv4Provider(): iterable
    {
        // High-value IPs that test unsigned integer conversion
        // ip2long('255.255.255.254') = -2 (signed) or 4294967294 (unsigned)
        yield 'broadcast minus 1' => ['255.255.255.254', true]; // Reserved range
        yield 'broadcast' => ['255.255.255.255', true]; // Reserved range
        yield 'multicast start' => ['224.0.0.0', true]; // Multicast
        yield 'multicast high' => ['239.255.255.255', true]; // Multicast
        yield 'class E reserved' => ['240.0.0.1', true]; // Reserved
        yield 'just below multicast' => ['223.255.255.255', false]; // Public
        yield 'high public ip' => ['200.200.200.200', false]; // Public
    }

    // =========================================================================
    // Mutation Testing: IPv4-mapped IPv6 substr (Line 263)
    // =========================================================================

    #[DataProvider('ipv4MappedHexProvider')]
    public function testIpv4MappedIpv6HexExtraction(string $ip, bool $shouldBlock): void
    {
        // Tests that the substr($hex, 24, 8) correctly extracts the IPv4 portion
        // from an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
        $result = $this->validator->isPrivateOrReserved($ip);
        $this->assertSame($shouldBlock, $result);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function ipv4MappedHexProvider(): iterable
    {
        // ::ffff:127.0.0.1 in hex: 00000000000000000000ffff7f000001
        // The last 8 hex chars (7f000001) = 127.0.0.1
        yield 'mapped loopback 127.0.0.1' => ['::ffff:127.0.0.1', true];
        yield 'mapped loopback 127.0.0.2' => ['::ffff:127.0.0.2', true];
        yield 'mapped loopback 127.255.255.255' => ['::ffff:127.255.255.255', true];

        // ::ffff:10.0.0.1 -> 0a000001
        yield 'mapped private 10.0.0.1' => ['::ffff:10.0.0.1', true];
        yield 'mapped private 10.255.255.255' => ['::ffff:10.255.255.255', true];

        // ::ffff:192.168.1.1 -> c0a80101
        yield 'mapped private 192.168.1.1' => ['::ffff:192.168.1.1', true];
        yield 'mapped private 192.168.255.255' => ['::ffff:192.168.255.255', true];

        // ::ffff:172.16.0.1 -> ac100001
        yield 'mapped private 172.16.0.1' => ['::ffff:172.16.0.1', true];
        yield 'mapped private 172.31.255.255' => ['::ffff:172.31.255.255', true];

        // ::ffff:169.254.169.254 -> a9fea9fe (cloud metadata)
        yield 'mapped link-local metadata' => ['::ffff:169.254.169.254', true];

        // Public IPs
        yield 'mapped public 8.8.8.8' => ['::ffff:8.8.8.8', false];
        yield 'mapped public 1.1.1.1' => ['::ffff:1.1.1.1', false];
        yield 'mapped public 93.184.216.34' => ['::ffff:93.184.216.34', false];
    }

    // =========================================================================
    // Mutation Testing: IPv4-translated addresses (Line 271)
    // =========================================================================

    #[DataProvider('ipv4TranslatedProvider')]
    public function testIpv4TranslatedAddresses(string $ip, bool $shouldBlock): void
    {
        // Tests ::ffff:0:x.x.x.x (IPv4-translated) format
        // These use the 0000000000000000ffff0000 prefix
        $result = $this->validator->isPrivateOrReserved($ip);
        $this->assertSame($shouldBlock, $result);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function ipv4TranslatedProvider(): iterable
    {
        yield 'translated loopback hex' => ['::ffff:0:127.0.0.1', true];
        yield 'translated private 10.x hex' => ['::ffff:0:10.0.0.1', true];
        yield 'translated public hex' => ['::ffff:0:8.8.8.8', false];
    }

    // =========================================================================
    // Mutation Testing: NAT64 prefix (Line 279)
    // =========================================================================

    #[DataProvider('nat64Provider')]
    public function testNat64Addresses(string $ip, bool $shouldBlock): void
    {
        // Tests 64:ff9b::/96 (NAT64 well-known prefix)
        $result = $this->validator->isPrivateOrReserved($ip);
        $this->assertSame($shouldBlock, $result);
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function nat64Provider(): iterable
    {
        yield 'nat64 loopback' => ['64:ff9b::127.0.0.1', true];
        yield 'nat64 private 10.x' => ['64:ff9b::10.0.0.1', true];
        yield 'nat64 private 192.168.x' => ['64:ff9b::192.168.1.1', true];
        yield 'nat64 metadata' => ['64:ff9b::169.254.169.254', true];
        yield 'nat64 public' => ['64:ff9b::8.8.8.8', false];
    }

    // =========================================================================
    // Mutation Testing: Logger called for IPv4 blocked (Line 127)
    // =========================================================================

    public function testLoggerIsCalledForBlockedIpv4(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                'SSRF protection: Blocked request to private/reserved host',
                $this->callback(fn(array $context): bool => $context['host'] === '192.168.1.1'
                    && $context['reason'] === 'Private IPv4 address')
            );

        $validator = new PrivateNetworkValidator($logger);
        $validator->isPrivateOrReserved('192.168.1.1');
    }

    // =========================================================================
    // Edge case: Invalid IPv6 should be blocked
    // =========================================================================

    public function testInvalidIpv6InsideBracketsIsNotTreatedAsIpv6(): void
    {
        // Invalid content inside brackets fails FILTER_VALIDATE_IP for IPv6
        // so extractIpv6 returns null and it's treated as a hostname
        $this->assertFalse($this->validator->isPrivateOrReserved('[not-an-ipv6]'));
    }

    // =========================================================================
    // DNS Timeout Configuration
    // =========================================================================

    public function testDefaultDnsTimeout(): void
    {
        $validator = new PrivateNetworkValidator();
        $this->assertSame(5.0, $validator->getDnsTimeout());
    }

    public function testCustomDnsTimeoutInConstructor(): void
    {
        $validator = new PrivateNetworkValidator(null, 10.0);
        $this->assertSame(10.0, $validator->getDnsTimeout());
    }

    public function testWithDnsTimeoutReturnsNewInstance(): void
    {
        $original = new PrivateNetworkValidator(null, 5.0);
        $modified = $original->withDnsTimeout(10.0);

        $this->assertNotSame($original, $modified);
        $this->assertSame(5.0, $original->getDnsTimeout());
        $this->assertSame(10.0, $modified->getDnsTimeout());
    }

    public function testWithDnsTimeoutPreservesLogger(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning');

        $validator = new PrivateNetworkValidator($logger, 5.0);
        $modified  = $validator->withDnsTimeout(10.0);

        // Verify the logger is still functional
        $modified->isPrivateOrReserved('127.0.0.1');
    }

    public function testWithDnsTimeoutRejectsZero(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('DNS timeout must be positive');

        $this->validator->withDnsTimeout(0.0);
    }

    public function testWithDnsTimeoutRejectsNegative(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('DNS timeout must be positive');

        $this->validator->withDnsTimeout(-1.0);
    }

    public function testWithDnsTimeoutAcceptsSmallPositiveValue(): void
    {
        $modified = $this->validator->withDnsTimeout(0.001);
        $this->assertSame(0.001, $modified->getDnsTimeout());
    }

    // =========================================================================
    // DnsResolver Injection Tests
    // =========================================================================

    public function testCustomDnsResolverIsUsed(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->with('example.com')
            ->willReturn(['8.8.8.8']);

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);
        $result    = $validator->isPrivateOrReserved('example.com');

        $this->assertFalse($result);
    }

    public function testCustomDnsResolverReturningPrivateIpBlocks(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->with('attacker-controlled.com')
            ->willReturn(['10.0.0.1']);

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);
        $result    = $validator->isPrivateOrReserved('attacker-controlled.com');

        $this->assertTrue($result);
    }

    public function testCustomDnsResolverReturningPrivateIpv6Blocks(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->with('attacker-controlled.com')
            ->willReturn(['::1']);

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);
        $result    = $validator->isPrivateOrReserved('attacker-controlled.com');

        $this->assertTrue($result);
    }

    public function testCustomDnsResolverReturningEmptyArrayAllows(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->with('nonexistent.example.com')
            ->willReturn([]);

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);
        $result    = $validator->isPrivateOrReserved('nonexistent.example.com');

        // Empty DNS response means no private IPs found, so allowed
        $this->assertFalse($result);
    }

    public function testCustomDnsResolverReturningMixedIpsBlocksOnPrivate(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->with('dual-homed.example.com')
            ->willReturn(['8.8.8.8', '192.168.1.1', '1.1.1.1']);

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);
        $result    = $validator->isPrivateOrReserved('dual-homed.example.com');

        // Should block because one of the IPs is private
        $this->assertTrue($result);
    }

    public function testWithDnsTimeoutPreservesCustomResolver(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->with('example.com')
            ->willReturn(['8.8.8.8']);

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);
        $modified  = $validator->withDnsTimeout(10.0);

        // The custom resolver should still be used after withDnsTimeout
        $result = $modified->isPrivateOrReserved('example.com');
        $this->assertFalse($result);
    }

    public function testDefaultResolverIsNativeDnsResolver(): void
    {
        // When no resolver is provided, a NativeDnsResolver should be used
        // We can verify this indirectly by checking that localhost resolves
        $validator = new PrivateNetworkValidator();

        // localhost should be blocked (either by hostname or by resolution)
        $this->assertTrue($validator->isPrivateOrReserved('localhost'));
    }

    public function testLoggerIsCalledForDnsResolvedPrivateIp(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                'SSRF protection: Blocked request to private/reserved host',
                $this->callback(fn(array $context): bool => $context['host'] === 'attacker.example.com'
                    && $context['reason'] === 'Resolved to private IPv4: 10.0.0.1')
            );

        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->with('attacker.example.com')
            ->willReturn(['10.0.0.1']);

        $validator = new PrivateNetworkValidator($logger, 5.0, $resolver);
        $validator->isPrivateOrReserved('attacker.example.com');
    }

    public function testLoggerIsCalledForDnsResolvedPrivateIpv6(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                'SSRF protection: Blocked request to private/reserved host',
                $this->callback(fn(array $context): bool => $context['host'] === 'attacker.example.com'
                    && $context['reason'] === 'Resolved to private IPv6: fe80::1')
            );

        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->with('attacker.example.com')
            ->willReturn(['fe80::1']);

        $validator = new PrivateNetworkValidator($logger, 5.0, $resolver);
        $validator->isPrivateOrReserved('attacker.example.com');
    }

    public function testDnsResolverNotCalledForDirectIpv4(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->never())->method('resolve');

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);

        // Direct IPv4 addresses should not trigger DNS resolution
        $validator->isPrivateOrReserved('8.8.8.8');
        $validator->isPrivateOrReserved('192.168.1.1');
    }

    public function testDnsResolverNotCalledForDirectIpv6(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->never())->method('resolve');

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);

        // Direct IPv6 addresses should not trigger DNS resolution
        $validator->isPrivateOrReserved('::1');
        $validator->isPrivateOrReserved('[2001:4860:4860::8888]');
    }

    public function testDnsResolverNotCalledForBlockedHostnames(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->never())->method('resolve');

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);

        // Blocked hostnames should be rejected before DNS resolution
        $validator->isPrivateOrReserved('localhost');
        $validator->isPrivateOrReserved('metadata.google.internal');
        $validator->isPrivateOrReserved('service.local');
    }

    public function testDnsResolverCalledForUnknownHostnames(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->exactly(2))
            ->method('resolve')
            ->willReturn(['8.8.8.8']);

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);

        // Unknown hostnames should trigger DNS resolution
        $validator->isPrivateOrReserved('example.com');
        $validator->isPrivateOrReserved('google.com');
    }

    public function testDnsResolverWithMultiplePrivateIpsBlocksOnFirst(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                'SSRF protection: Blocked request to private/reserved host',
                $this->callback(fn(array $context): bool => $context['reason'] === 'Resolved to private IPv4: 127.0.0.1')
            );

        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->willReturn(['127.0.0.1', '10.0.0.1', '192.168.1.1']);

        $validator = new PrivateNetworkValidator($logger, 5.0, $resolver);
        $result    = $validator->isPrivateOrReserved('multi-private.example.com');

        $this->assertTrue($result);
    }

    public function testDnsResolverWithInvalidIpInResponseSkipsIt(): void
    {
        $resolver = $this->createMock(DnsResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->willReturn(['not-an-ip', '8.8.8.8']);

        $validator = new PrivateNetworkValidator(null, 5.0, $resolver);
        $result    = $validator->isPrivateOrReserved('weird-resolver.example.com');

        // Invalid IPs in the response are skipped, valid public IP allows
        $this->assertFalse($result);
    }
}
