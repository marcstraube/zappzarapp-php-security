<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Pwned;

/**
 * Simple HTTP client interface for HIBP API
 *
 * Compatible with PSR-18 clients but simpler for our use case.
 */
interface HttpClientInterface
{
    /**
     * Fetch content from a URL
     *
     * @param string $url The URL to fetch
     *
     * @return string|null Response body or null on error
     */
    public function get(string $url): ?string;
}
