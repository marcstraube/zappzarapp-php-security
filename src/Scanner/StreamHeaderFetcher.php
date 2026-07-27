<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Scanner;

use Override;
use Zappzarapp\Security\Scanner\Exception\ScanException;

/**
 * Header fetcher using PHP's HTTP stream wrapper
 *
 * Performs a GET request (some servers reject HEAD), follows up to five
 * redirects, and returns the headers of the final response. Error responses
 * (4xx/5xx) are scanned like any other response - their security headers
 * matter too.
 *
 * Note: this fetcher is meant for the CLI scanner, where the operator
 * chooses the target deliberately. Do not expose it to user-supplied URLs
 * in a web application without SSRF protection (see UriSanitizer).
 */
final readonly class StreamHeaderFetcher implements HeaderFetcherInterface
{
    /**
     * Request timeout in seconds
     */
    private const int TIMEOUT_SECONDS = 10;

    /**
     * Maximum number of redirects to follow
     */
    private const int MAX_REDIRECTS = 5;

    #[Override]
    public function fetch(string $url): array
    {
        $this->assertScannableUrl($url);

        // @codeCoverageIgnoreStart
        // Network I/O - the raw fetch is exercised via the normalization
        // logic below and end-to-end by the CLI itself.
        $context = stream_context_create([
            'http' => [
                'method'          => 'GET',
                'timeout'         => self::TIMEOUT_SECONDS,
                'follow_location' => 1,
                'max_redirects'   => self::MAX_REDIRECTS,
                'ignore_errors'   => true,
                'user_agent'      => 'zappzarapp-security-scanner',
            ],
        ]);

        $headers = @get_headers($url, true, $context);

        if ($headers === false) {
            throw ScanException::fetchFailed($url);
        }

        return $this->normalizeHeaders($headers);
        // @codeCoverageIgnoreEnd
    }

    /**
     * Normalize a get_headers() associative result to a flat name => value map
     *
     * get_headers() lists status lines under integer keys and turns headers
     * that appeared in multiple responses (redirect chains) into arrays -
     * the last element belongs to the final response.
     *
     * @param array<int|string, string|array<int, string>> $headers
     *
     * @return array<string, string>
     */
    public function normalizeHeaders(array $headers): array
    {
        $normalized = [];

        foreach ($headers as $name => $value) {
            if (is_int($name)) {
                // Status line (one per response in a redirect chain)
                continue;
            }

            if (is_array($value)) {
                $last = end($value);

                if ($last === false) {
                    continue;
                }

                $normalized[$name] = $last;
                continue;
            }

            $normalized[$name] = $value;
        }

        return $normalized;
    }

    /**
     * Reject URLs that are not scannable http(s) URLs
     *
     * @throws ScanException If the URL is invalid
     */
    private function assertScannableUrl(string $url): void
    {
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw ScanException::invalidUrl($url);
        }

        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

        if (!in_array($scheme, ['http', 'https'], true)) {
            throw ScanException::invalidUrl($url);
        }
    }
}
