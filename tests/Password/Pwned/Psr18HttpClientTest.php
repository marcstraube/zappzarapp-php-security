<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Pwned;

use Exception;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Zappzarapp\Security\Password\Pwned\Psr18HttpClient;

#[CoversClass(Psr18HttpClient::class)]
final class Psr18HttpClientTest extends TestCase
{
    private ClientInterface&Stub $client;

    private RequestFactoryInterface&Stub $requestFactory;

    private RequestInterface&Stub $request;

    private Psr18HttpClient $httpClient;

    protected function setUp(): void
    {
        $this->client         = $this->createStub(ClientInterface::class);
        $this->requestFactory = $this->createStub(RequestFactoryInterface::class);
        $this->request        = $this->createStub(RequestInterface::class);

        $this->httpClient = new Psr18HttpClient($this->client, $this->requestFactory);
    }

    #[Test]
    public function testGetReturnsResponseBody(): void
    {
        $url          = 'https://api.pwnedpasswords.com/range/ABCDE';
        $responseBody = "SUFFIX1:123\r\nSUFFIX2:456";

        $stream = $this->createStub(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getBody')->willReturn($stream);

        $this->request->method('withHeader')->willReturn($this->request);
        $this->requestFactory->method('createRequest')->willReturn($this->request);
        $this->client->method('sendRequest')->willReturn($response);

        $result = $this->httpClient->get($url);

        $this->assertSame($responseBody, $result);
    }

    #[Test]
    public function testGetReturnsNullOnNon200Status(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(404);

        $this->request->method('withHeader')->willReturn($this->request);
        $this->requestFactory->method('createRequest')->willReturn($this->request);
        $this->client->method('sendRequest')->willReturn($response);

        $result = $this->httpClient->get('https://example.com');

        $this->assertNull($result);
    }

    #[Test]
    public function testGetReturnsNullOnClientException(): void
    {
        $exception = new class extends Exception implements ClientExceptionInterface {};

        $this->request->method('withHeader')->willReturn($this->request);
        $this->requestFactory->method('createRequest')->willReturn($this->request);
        $this->client->method('sendRequest')->willThrowException($exception);

        $result = $this->httpClient->get('https://example.com');

        $this->assertNull($result);
    }

    #[Test]
    public function testGetSetsUserAgentHeader(): void
    {
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn(200);
        $response->method('getBody')->willReturn($this->createStub(StreamInterface::class));

        $request = $this->createMock(RequestInterface::class);
        $request->expects($this->once())
            ->method('withHeader')
            ->with('User-Agent', 'zappzarapp-security-php')
            ->willReturn($request);

        $requestFactory = $this->createMock(RequestFactoryInterface::class);
        $requestFactory->method('createRequest')
            ->with('GET', 'https://example.com')
            ->willReturn($request);

        $client = $this->createStub(ClientInterface::class);
        $client->method('sendRequest')->willReturn($response);

        $httpClient = new Psr18HttpClient($client, $requestFactory);
        $httpClient->get('https://example.com');
    }
}
