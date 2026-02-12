<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Uri;

use InvalidArgumentException;
use Psr\Log\LoggerInterface;

/**
 * Validates URIs against private/internal network addresses
 *
 * Used for SSRF (Server-Side Request Forgery) protection when
 * making server-side HTTP requests.
 *
 * @psalm-immutable
 */
final readonly class PrivateNetworkValidator
{
    private DnsResolver $resolver;

    /**
     * IPv4 private ranges (RFC 1918)
     * - 10.0.0.0/8
     * - 172.16.0.0/12
     * - 192.168.0.0/16
     *
     * @var list<array{start: int, end: int}>
     */
    private const array IPV4_PRIVATE_RANGES = [
        ['start' => 0x0A000000, 'end' => 0x0AFFFFFF], // 10.0.0.0/8
        ['start' => 0xAC100000, 'end' => 0xAC1FFFFF], // 172.16.0.0/12
        ['start' => 0xC0A80000, 'end' => 0xC0A8FFFF], // 192.168.0.0/16
    ];

    /**
     * IPv4 loopback range (127.0.0.0/8)
     */
    private const int IPV4_LOOPBACK_START = 0x7F000000;

    private const int IPV4_LOOPBACK_END   = 0x7FFFFFFF;

    /**
     * IPv4 link-local range (169.254.0.0/16)
     * Includes cloud metadata endpoints (169.254.169.254)
     */
    private const int IPV4_LINK_LOCAL_START = 0xA9FE0000;

    private const int IPV4_LINK_LOCAL_END   = 0xA9FEFFFF;

    /**
     * Reserved/special purpose ranges that should be blocked for SSRF
     *
     * @var list<array{start: int, end: int}>
     */
    private const array IPV4_RESERVED_RANGES = [
        ['start' => 0x00000000, 'end' => 0x00FFFFFF], // 0.0.0.0/8 (current network)
        ['start' => 0x64400000, 'end' => 0x647FFFFF], // 100.64.0.0/10 (carrier-grade NAT)
        ['start' => 0xC0000000, 'end' => 0xC00000FF], // 192.0.0.0/24 (IETF protocol assignments)
        ['start' => 0xC0000200, 'end' => 0xC00002FF], // 192.0.2.0/24 (TEST-NET-1)
        ['start' => 0xC6336400, 'end' => 0xC63364FF], // 198.51.100.0/24 (TEST-NET-2)
        ['start' => 0xCB007100, 'end' => 0xCB0071FF], // 203.0.113.0/24 (TEST-NET-3)
        ['start' => 0xE0000000, 'end' => 0xEFFFFFFF], // 224.0.0.0/4 (multicast)
        ['start' => 0xF0000000, 'end' => 0xFFFFFFFF], // 240.0.0.0/4 (reserved/broadcast)
    ];

    /**
     * Internal/dangerous hostnames that should always be blocked
     *
     * @var list<string>
     */
    private const array BLOCKED_HOSTNAMES = [
        'localhost',
        'localhost.localdomain',
        'ip6-localhost',
        'ip6-loopback',
        'metadata.google.internal',
        'metadata.google.internal.',
        'kubernetes.default.svc',
        'kubernetes.default',
    ];

    /**
     * @param LoggerInterface|null $logger      Optional PSR-3 logger for blocked request warnings
     * @param float                $dnsTimeout  DNS timeout in seconds (reserved for future use)
     * @param DnsResolver|null     $dnsResolver DNS resolver for hostname resolution (default: NativeDnsResolver)
     */
    public function __construct(
        private ?LoggerInterface $logger = null,
        private float $dnsTimeout = 5.0,
        ?DnsResolver $dnsResolver = null,
    ) {
        $this->resolver = $dnsResolver ?? new NativeDnsResolver();
    }

    /**
     * Create a new instance with a different DNS timeout
     *
     * @param float $seconds Timeout in seconds (must be positive)
     *
     * @return self A new instance with the updated timeout
     */
    public function withDnsTimeout(float $seconds): self
    {
        if ($seconds <= 0.0) {
            throw new InvalidArgumentException('DNS timeout must be positive');
        }

        return new self($this->logger, $seconds, $this->resolver);
    }

    /**
     * Get the configured DNS timeout
     */
    public function getDnsTimeout(): float
    {
        return $this->dnsTimeout;
    }

    /**
     * Check if a host resolves to a private or reserved IP address
     *
     * DNS resolution happens at validation time to catch DNS rebinding attacks.
     *
     * @param string $host The hostname or IP address to validate
     *
     * @return bool True if the host is private/reserved and should be blocked
     */
    public function isPrivateOrReserved(string $host): bool
    {
        $host = strtolower(trim($host));

        if ($host === '') {
            return true;
        }

        // Check blocked hostnames first
        if ($this->isBlockedHostname($host)) {
            $this->logBlocked($host, 'Blocked hostname');

            return true;
        }

        // Check if it's an IPv6 address (bracketed or not)
        $ipv6 = $this->extractIpv6($host);
        if ($ipv6 !== null) {
            if ($this->isPrivateIpv6($ipv6)) {
                $this->logBlocked($host, 'Private IPv6 address');

                return true;
            }

            return false;
        }

        // Check if it's a raw IPv4 address
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            if ($this->isPrivateIpv4($host)) {
                $this->logBlocked($host, 'Private IPv4 address');

                return true;
            }

            return false;
        }

        // Resolve hostname to IP addresses
        $ips = $this->resolveHost($host);

        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                if ($this->isPrivateIpv4($ip)) {
                    $this->logBlocked($host, 'Resolved to private IPv4: ' . $ip);

                    return true;
                }
            } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                if ($this->isPrivateIpv6($ip)) {
                    $this->logBlocked($host, 'Resolved to private IPv6: ' . $ip);

                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if a hostname is in the blocked hostnames list
     */
    private function isBlockedHostname(string $host): bool
    {
        // Direct match
        if (in_array($host, self::BLOCKED_HOSTNAMES, true)) {
            return true;
        }

        // Check for .internal suffix (common cloud internal domains)
        if (str_ends_with($host, '.internal') || str_ends_with($host, '.internal.')) {
            return true;
        }

        // Check for .local suffix (mDNS)
        return str_ends_with($host, '.local') || str_ends_with($host, '.local.');
    }

    /**
     * Extract IPv6 address from host (handles bracketed notation)
     */
    private function extractIpv6(string $host): ?string
    {
        // Remove brackets if present (URI notation)
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $host = substr($host, 1, -1);
        }

        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return $host;
        }

        return null;
    }

    /**
     * Check if an IPv4 address is private or reserved
     */
    private function isPrivateIpv4(string $ip): bool
    {
        $long = ip2long($ip);
        if ($long === false) {
            return true; // Invalid IP, block it
        }

        // Convert to unsigned for proper comparison
        $long = (int) sprintf('%u', $long);

        // Check loopback (127.0.0.0/8)
        if ($long >= self::IPV4_LOOPBACK_START && $long <= self::IPV4_LOOPBACK_END) {
            return true;
        }

        // Check link-local (169.254.0.0/16) - includes cloud metadata
        if ($long >= self::IPV4_LINK_LOCAL_START && $long <= self::IPV4_LINK_LOCAL_END) {
            return true;
        }

        // Check private ranges (RFC 1918)
        if (array_any(self::IPV4_PRIVATE_RANGES, static fn(array $range): bool => $long >= $range['start'] && $long <= $range['end'])) {
            return true;
        }

        return array_any(self::IPV4_RESERVED_RANGES, static fn(array $range): bool => $long >= $range['start'] && $long <= $range['end']);
    }

    /**
     * Check if an IPv6 address is private or reserved
     */
    private function isPrivateIpv6(string $ip): bool
    {
        // Normalize the IPv6 address
        $packed = inet_pton($ip);
        if ($packed === false) {
            return true; // Invalid IP, block it
        }

        $hex = bin2hex($packed);

        // ::1 (loopback)
        if ($hex === '00000000000000000000000000000001') {
            return true;
        }

        // :: (unspecified)
        if ($hex === '00000000000000000000000000000000') {
            return true;
        }

        // fc00::/7 (unique local address)
        $firstByte = hexdec(substr($hex, 0, 2));
        if (($firstByte & 0xFE) === 0xFC) {
            return true;
        }

        // fe80::/10 (link-local)
        $firstWord = hexdec(substr($hex, 0, 4));
        if (($firstWord & 0xFFC0) === 0xFE80) {
            return true;
        }

        // ::ffff:0:0/96 (IPv4-mapped IPv6) - check the embedded IPv4
        if (str_starts_with($hex, '00000000000000000000ffff')) {
            $ipv4Hex = substr($hex, 24, 8);
            $ipv4Int = hexdec($ipv4Hex);
            $ipv4    = long2ip((int) $ipv4Int);

            return $this->isPrivateIpv4($ipv4);
        }

        // ::ffff:0:0:0/96 (IPv4-translated addresses)
        if (str_starts_with($hex, '0000000000000000ffff0000')) {
            $ipv4Hex = substr($hex, 24, 8);
            $ipv4Int = hexdec($ipv4Hex);
            $ipv4    = long2ip((int) $ipv4Int);

            return $this->isPrivateIpv4($ipv4);
        }

        // 64:ff9b::/96 (NAT64)
        if (str_starts_with($hex, '0064ff9b00000000')) {
            $ipv4Hex = substr($hex, 24, 8);
            $ipv4Int = hexdec($ipv4Hex);
            $ipv4    = long2ip((int) $ipv4Int);

            return $this->isPrivateIpv4($ipv4);
        }

        return false;
    }

    /**
     * Resolve a hostname to IP addresses using the configured resolver
     *
     * @return list<string>
     */
    private function resolveHost(string $host): array
    {
        return $this->resolver->resolve($host);
    }

    /**
     * Log a blocked request
     */
    private function logBlocked(string $host, string $reason): void
    {
        $this->logger?->warning(
            'SSRF protection: Blocked request to private/reserved host',
            [
                'host'   => $host,
                'reason' => $reason,
            ]
        );
    }
}
