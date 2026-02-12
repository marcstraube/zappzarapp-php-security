<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sri\FileGetContentsHttpClient;
use Zappzarapp\Security\Sri\HttpClientInterface;

#[CoversClass(FileGetContentsHttpClient::class)]
final class HttpClientInterfaceTest extends TestCase
{
    public function testFileGetContentsHttpClientImplementsInterface(): void
    {
        $client = new FileGetContentsHttpClient();

        $this->assertInstanceOf(HttpClientInterface::class, $client);
    }

    public function testFileGetContentsHttpClientWithDefaultSettings(): void
    {
        $client = new FileGetContentsHttpClient();

        // We can't easily test actual HTTP calls, but we can verify the class instantiates
        $this->assertInstanceOf(FileGetContentsHttpClient::class, $client);
    }

    public function testFileGetContentsHttpClientWithCustomSettings(): void
    {
        $client = new FileGetContentsHttpClient(
            defaultTimeout: 30,
            defaultUserAgent: 'Custom/1.0'
        );

        $this->assertInstanceOf(FileGetContentsHttpClient::class, $client);
    }

    public function testGetReturnsNullForInvalidUrl(): void
    {
        $client = new FileGetContentsHttpClient();

        // This will fail to connect and return null
        $result = $client->get('http://localhost:99999/nonexistent');

        $this->assertNull($result);
    }
}
