<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Sri;

use Override;

/**
 * Default HTTP client using file_get_contents
 *
 * For production use, consider replacing with a PSR-18 compatible client.
 */
final readonly class FileGetContentsHttpClient implements HttpClientInterface
{
    public function __construct(
        private int $defaultTimeout = 10,
        private string $defaultUserAgent = 'Zappzarapp-Security-SRI/1.0',
    ) {
    }

    #[Override]
    public function get(string $url, array $options = []): ?string
    {
        // Validate URL scheme (SSRF prevention)
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (!is_string($scheme) || !in_array(strtolower($scheme), ['http', 'https'], true)) {
            return null;
        }

        $timeout         = $options['timeout'] ?? $this->defaultTimeout;
        $followRedirects = $options['follow_redirects'] ?? true;
        $maxRedirects    = $options['max_redirects'] ?? 5;
        $userAgent       = $options['user_agent'] ?? $this->defaultUserAgent;

        return $this->doRequest($url, $timeout, $followRedirects, $maxRedirects, $userAgent);
    }

    /**
     * Perform the actual HTTP request
     *
     * @codeCoverageIgnore Network I/O cannot be unit tested
     */
    private function doRequest(
        string $url,
        int $timeout,
        bool $followRedirects,
        int $maxRedirects,
        string $userAgent,
    ): ?string {
        $context = stream_context_create([
            'http' => [
                'method'          => 'GET',
                'timeout'         => $timeout,
                'follow_location' => $followRedirects ? 1 : 0,
                'max_redirects'   => $maxRedirects,
                'header'          => [
                    'User-Agent: ' . $userAgent,
                    'Accept: */*',
                ],
                'ignore_errors' => false,
            ],
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ],
        ]);

        set_error_handler(static fn(): bool => true);
        try {
            $content = file_get_contents($url, false, $context);
        } finally {
            restore_error_handler();
        }

        if ($content === false) {
            return null;
        }

        return $content;
    }
}
