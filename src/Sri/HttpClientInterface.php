<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sri;

/**
 * HTTP client interface for resource fetching
 *
 * Simple interface for fetching remote resources.
 * Compatible with PSR-18 adapters but simpler for our use case.
 */
interface HttpClientInterface
{
    /**
     * Fetch content from a URL
     *
     * @param string $url The URL to fetch
     * @param array{
     *     timeout?: int,
     *     follow_redirects?: bool,
     *     max_redirects?: int,
     *     user_agent?: string
     * } $options Request options
     *
     * @return string|null Response body or null on error
     */
    public function get(string $url, array $options = []): ?string;
}
