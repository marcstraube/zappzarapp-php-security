<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Uri;

/**
 * DNS resolver interface for testable hostname resolution
 *
 * This interface allows for dependency injection of DNS resolution,
 * enabling proper unit testing without actual network calls.
 */
interface DnsResolver
{
    /**
     * Resolve hostname to IP addresses
     *
     * @param string $host Hostname to resolve
     *
     * @return list<string> List of resolved IP addresses (IPv4 and/or IPv6)
     */
    public function resolve(string $host): array;
}
