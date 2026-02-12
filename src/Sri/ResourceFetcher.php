<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sri;

use Zappzarapp\Security\Sanitization\Uri\PrivateNetworkValidator;
use Zappzarapp\Security\Sri\Exception\FetchException;

/**
 * Fetches remote resources for SRI hash generation
 *
 * Uses HttpClientInterface for HTTP requests, defaulting to file_get_contents.
 * For production, inject a PSR-18 compatible adapter.
 *
 * ## SSRF Protection
 *
 * This class includes built-in SSRF (Server-Side Request Forgery) protection
 * via {@see PrivateNetworkValidator}. Requests to private networks, loopback
 * addresses, link-local addresses, and cloud metadata endpoints are blocked
 * by default.
 *
 * To disable SSRF protection (NOT recommended for production):
 * ```php
 * $fetcher = new ResourceFetcher(ssrfValidator: null);
 * ```
 */
final readonly class ResourceFetcher
{
    public function __construct(private ResourceFetcherConfig $config = new ResourceFetcherConfig(), private HttpClientInterface $client = new FileGetContentsHttpClient(), private ?PrivateNetworkValidator $ssrfValidator = new PrivateNetworkValidator())
    {
    }

    /**
     * Fetch resource content from URL
     *
     * @param string $url The URL to fetch
     *
     * @return string The resource content
     *
     * @throws FetchException If fetching fails
     */
    public function fetch(string $url): string
    {
        // Validate URL
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw FetchException::invalidUrl($url);
        }

        $parsedUrl = parse_url($url);
        if ($parsedUrl === false || !isset($parsedUrl['scheme'])) {
            throw FetchException::invalidUrl($url);
        }

        // SSRF Protection first (more critical than scheme validation)
        $host = $parsedUrl['host'] ?? '';
        if ($this->ssrfValidator instanceof PrivateNetworkValidator && $this->ssrfValidator->isPrivateOrReserved($host)) {
            throw FetchException::ssrfBlocked($url, $host);
        }

        // Validate scheme based on configuration
        $scheme = strtolower($parsedUrl['scheme']);
        if ($this->config->requireHttps) {
            if ($scheme !== 'https') {
                throw FetchException::failed(
                    $url,
                    'HTTPS required. Use ResourceFetcherConfig::development() for local HTTP testing.'
                );
            }
        } elseif (!in_array($scheme, ['https', 'http'], true)) {
            throw FetchException::failed($url, 'Only HTTP(S) URLs are supported');
        }

        // Fetch via HTTP client
        $content = $this->client->get($url, [
            'timeout'          => $this->config->timeout,
            'follow_redirects' => $this->config->followRedirects,
            'max_redirects'    => $this->config->maxRedirects,
            'user_agent'       => $this->config->userAgent,
        ]);

        if ($content === null) {
            $error = error_get_last();
            throw FetchException::failed($url, $error['message'] ?? 'Unknown error');
        }

        // Check size limit
        if (strlen($content) > $this->config->maxSize) {
            throw FetchException::failed($url, sprintf(
                'Resource exceeds maximum size (%d bytes)',
                $this->config->maxSize
            ));
        }

        return $content;
    }

    /**
     * Fetch and generate integrity attribute
     *
     * @param string $url The URL to fetch
     * @param HashAlgorithm $algorithm The hash algorithm to use
     *
     * @return IntegrityAttribute The generated integrity attribute
     *
     * @throws FetchException If fetching fails
     */
    public function fetchAndHash(
        string $url,
        HashAlgorithm $algorithm = HashAlgorithm::SHA384,
    ): IntegrityAttribute {
        $content = $this->fetch($url);

        return IntegrityAttribute::fromContent($content, $algorithm);
    }
}
