<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Pwned;

use Override;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * PSR-18 HTTP client adapter for HIBP API
 *
 * Wraps a PSR-18 HTTP client for use with PwnedPasswordChecker.
 * Requires psr/http-client and psr/http-factory implementations.
 *
 * ## Usage
 *
 * ```php
 * use GuzzleHttp\Client;
 * use GuzzleHttp\Psr7\HttpFactory;
 *
 * $httpClient = new Psr18HttpClient(
 *     new Client(['timeout' => 5]),
 *     new HttpFactory()
 * );
 *
 * $checker = new PwnedPasswordChecker($httpClient);
 * ```
 */
final readonly class Psr18HttpClient implements HttpClientInterface
{
    private const string USER_AGENT = 'zappzarapp-security-php';

    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requestFactory,
    ) {
    }

    #[Override]
    public function get(string $url): ?string
    {
        try {
            $request = $this->requestFactory->createRequest('GET', $url)
                ->withHeader('User-Agent', self::USER_AGENT);

            $response = $this->client->sendRequest($request);

            if ($response->getStatusCode() !== 200) {
                return null;
            }

            return $response->getBody()->getContents();
        } catch (ClientExceptionInterface) {
            return null;
        }
    }

}
