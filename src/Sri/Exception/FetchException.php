<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sri\Exception;

use RuntimeException;

/**
 * Exception thrown when fetching a resource fails
 */
final class FetchException extends RuntimeException
{
    /**
     * Create for fetch failure
     */
    public static function failed(string $url, string $reason): self
    {
        return new self(sprintf(
            'Failed to fetch resource from "%s": %s',
            $url,
            $reason
        ));
    }

    /**
     * Create for timeout
     */
    public static function timeout(string $url): self
    {
        return new self(sprintf(
            'Timeout while fetching resource from "%s"',
            $url
        ));
    }

    /**
     * Create for invalid URL
     */
    public static function invalidUrl(string $url): self
    {
        return new self(sprintf(
            'Invalid URL: %s',
            $url
        ));
    }

    /**
     * Create for SSRF protection block
     */
    public static function ssrfBlocked(string $url, string $host): self
    {
        return new self(sprintf(
            'SSRF protection: Request to "%s" blocked (host "%s" resolves to private/reserved address)',
            $url,
            $host
        ));
    }
}
