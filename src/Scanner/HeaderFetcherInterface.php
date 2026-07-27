<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Scanner;

use Zappzarapp\Security\Scanner\Exception\ScanException;

/**
 * Fetches HTTP response headers for a URL
 */
interface HeaderFetcherInterface
{
    /**
     * Fetch the response headers of the final response (after redirects)
     *
     * @return array<string, string> Header name => value map
     *
     * @throws ScanException If the URL is invalid or the request fails
     */
    public function fetch(string $url): array;
}
