<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Uri;

/**
 * Native DNS resolver using PHP's built-in DNS functions
 *
 * Uses gethostbyname() for IPv4 and dns_get_record() for A/AAAA records.
 *
 * Note: PHP's native DNS functions do not support timeouts directly.
 * For production use with strict timeout requirements, consider:
 * - Using a caching DNS resolver
 * - Implementing a custom resolver with ReactPHP/Amp
 * - Setting system-level DNS timeout via resolv.conf
 */
class NativeDnsResolver implements DnsResolver
{
    /**
     * @inheritDoc
     */
    public function resolve(string $host): array
    {
        $ips = [];

        // Try gethostbyname for IPv4
        $ipv4 = $this->resolveViaGethostbyname($host);
        if ($ipv4 !== null) {
            $ips[] = $ipv4;
        }

        // Try dns_get_record for both A and AAAA records
        $records = $this->resolveViaDnsGetRecord($host);
        foreach ($records as $record) {
            if (isset($record['ip']) && is_string($record['ip'])) {
                $ips[] = $record['ip'];
            }

            if (isset($record['ipv6']) && is_string($record['ipv6'])) {
                $ips[] = $record['ipv6'];
            }
        }

        return array_values(array_unique($ips));
    }

    /**
     * Resolve IPv4 address via gethostbyname
     *
     * @return string|null The IPv4 address or null if resolution failed
     */
    protected function resolveViaGethostbyname(string $host): ?string
    {
        $ipv4 = gethostbyname($host);

        return $ipv4 !== $host ? $ipv4 : null;
    }

    /**
     * Resolve DNS records via dns_get_record
     *
     * @return list<array<string, mixed>>
     */
    protected function resolveViaDnsGetRecord(string $host): array
    {
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);

        if ($records === false) {
            return [];
        }

        return $records;
    }
}
