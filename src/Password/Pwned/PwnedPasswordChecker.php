<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Pwned;

use RuntimeException;
use SensitiveParameter;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;
use Zappzarapp\Security\Password\Exception\PwnedPasswordException;
use Zappzarapp\Security\Password\Security\ClearsMemory;

/**
 * HIBP Pwned Passwords checker using k-Anonymity
 *
 * Checks passwords against the Have I Been Pwned database
 * using the k-Anonymity model (only first 5 chars of SHA-1 sent).
 *
 * @see https://haveibeenpwned.com/API/v3#PwnedPasswords
 */
final readonly class PwnedPasswordChecker
{
    use ClearsMemory;

    public function __construct(
        private HttpClientInterface $client,
        private PwnedCheckerConfig $config = new PwnedCheckerConfig(),
        private ?SecurityLoggerInterface $logger = null,
    ) {
    }

    /**
     * Check if password is in breach database
     *
     * @param string $password The password to check
     *
     * @return int Number of occurrences (0 = not found)
     */
    public function check(#[SensitiveParameter] string $password): int
    {
        return $this->withClearedMemory($password, function (string $pwd): int {
            // Hash password with SHA-1
            $hash   = strtoupper(sha1($pwd));
            $prefix = substr($hash, 0, 5);
            $suffix = substr($hash, 5);

            // Fetch matching hashes from API
            $response = $this->fetchFromApi($prefix);

            if ($response === null) {
                // Fail-closed: treat as compromised when API is unavailable
                // Fail-open: treat as not found (legacy behavior)
                return $this->config->failClosed
                    ? PwnedCheckerConfig::FAIL_CLOSED_COUNT
                    : 0;
            }

            // Search for our suffix in the response
            return $this->findOccurrences($response, $suffix);
        });
    }

    /**
     * Check and throw if password is compromised
     *
     * @throws PwnedPasswordException If password is found in breach database
     * @throws RuntimeException If API call fails and throwOnError is true
     */
    public function checkAndThrow(#[SensitiveParameter] string $password): void
    {
        $occurrences = $this->check($password);

        if ($occurrences >= $this->config->minOccurrences) {
            throw PwnedPasswordException::breached($occurrences);
        }
    }

    /**
     * Check if password is compromised (boolean)
     */
    public function isCompromised(#[SensitiveParameter] string $password): bool
    {
        $occurrences   = $this->check($password);
        $isCompromised = $occurrences >= $this->config->minOccurrences;

        if ($isCompromised) {
            $this->logger?->alert('Compromised password detected', [
                'occurrences'      => $occurrences,
                'min_occurrences'  => $this->config->minOccurrences,
                'fail_closed_mode' => $occurrences === PwnedCheckerConfig::FAIL_CLOSED_COUNT,
            ]);
        }

        return $isCompromised;
    }

    /**
     * Fetch hash suffixes from HIBP API
     *
     * @return string|null Response body or null on error
     *
     * @throws RuntimeException If API call fails and throwOnError is true
     * @throws RuntimeException If URL scheme is not HTTPS (SSRF prevention)
     */
    private function fetchFromApi(string $prefix): ?string
    {
        $url = $this->config->apiUrl . $prefix;

        // Validate URL scheme (SSRF prevention - Defense in Depth)
        // Only HTTPS is allowed to prevent:
        // - HTTP downgrade attacks exposing password hash prefixes
        // - SSRF via file://, gopher://, dict://, etc.
        // Note: PwnedCheckerConfig already validates HTTPS at construction time.
        // This runtime check is unreachable in normal usage but provides
        // defense against reflection-based bypasses of config validation.
        $scheme = parse_url($url, PHP_URL_SCHEME);
        // @codeCoverageIgnoreStart - Defense in Depth (config already validates HTTPS)
        if ($scheme !== 'https') {
            throw new RuntimeException('Only HTTPS URLs are allowed for HIBP API');
        }

        // @codeCoverageIgnoreEnd

        $response = $this->client->get($url);

        if ($response === null && $this->config->throwOnError) {
            throw new RuntimeException('Failed to fetch from HIBP API');
        }

        return $response;
    }

    /**
     * Find occurrences of hash suffix in API response
     */
    private function findOccurrences(string $response, string $suffix): int
    {
        // Response format: "SUFFIX:COUNT\r\n"
        $lines = explode("\r\n", $response);

        foreach ($lines as $line) {
            if ($line === '') {
                continue;
            }

            $parts = explode(':', $line);
            if (count($parts) !== 2) {
                continue;
            }

            if (hash_equals($suffix, $parts[0])) {
                return (int) $parts[1];
            }
        }

        return 0;
    }
}
