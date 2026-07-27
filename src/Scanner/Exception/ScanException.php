<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Scanner\Exception;

use RuntimeException;

/**
 * Exception thrown when a header scan cannot be performed
 */
final class ScanException extends RuntimeException
{
    /**
     * Create for a URL that is not a valid http(s) URL
     */
    public static function invalidUrl(string $url): self
    {
        return new self(sprintf(
            'Invalid URL "%s" (only http:// and https:// URLs can be scanned)',
            $url
        ));
    }

    /**
     * Create for a request that failed
     */
    public static function fetchFailed(string $url): self
    {
        return new self(sprintf(
            'Could not fetch response headers from "%s" (network error or unreachable host)',
            $url
        ));
    }
}
