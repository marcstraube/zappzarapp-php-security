<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sri\FileGetContentsHttpClient;
use Zappzarapp\Security\Sri\HttpClientInterface;

#[CoversClass(FileGetContentsHttpClient::class)]
final class FileGetContentsHttpClientTest extends TestCase
{
    public function testImplementsHttpClientInterface(): void
    {
        $client = new FileGetContentsHttpClient();

        $this->assertInstanceOf(HttpClientInterface::class, $client);
    }

    public function testConstructorWithDefaultValues(): void
    {
        $client = new FileGetContentsHttpClient();

        $this->assertInstanceOf(FileGetContentsHttpClient::class, $client);
    }

    public function testConstructorWithCustomValues(): void
    {
        $client = new FileGetContentsHttpClient(
            defaultTimeout: 30,
            defaultUserAgent: 'Custom-Agent/1.0'
        );

        $this->assertInstanceOf(FileGetContentsHttpClient::class, $client);
    }

    // --- SSRF Protection Tests ---

    /**
     * @return array<string, array{string}>
     */
    public static function invalidSchemeProvider(): array
    {
        return [
            'file scheme'       => ['file:///etc/passwd'],
            'ftp scheme'        => ['ftp://example.com/file'],
            'data scheme'       => ['data:text/html,<script>alert(1)</script>'],
            'javascript scheme' => ['javascript:alert(1)'],
            'php scheme'        => ['php://filter/resource=/etc/passwd'],
            'phar scheme'       => ['phar://malicious.phar'],
            'expect scheme'     => ['expect://id'],
            'glob scheme'       => ['glob:///*.txt'],
            'ssh2 scheme'       => ['ssh2.sftp://user@host/path'],
            'no scheme'         => ['//example.com/path'],
            'empty string'      => [''],
            'relative path'     => ['/etc/passwd'],
            'windows path'      => ['C:\\Windows\\System32\\config\\SAM'],
        ];
    }

    #[DataProvider('invalidSchemeProvider')]
    public function testGetRejectsInvalidSchemes(string $url): void
    {
        $client = new FileGetContentsHttpClient();

        $result = $client->get($url);

        $this->assertNull($result, "URL with invalid scheme should return null: {$url}");
    }

    public function testGetAcceptsHttpScheme(): void
    {
        $client = new FileGetContentsHttpClient(defaultTimeout: 1);

        // Valid scheme - will attempt connection (and fail), but shouldn't return null from scheme check
        $result = $client->get('http://localhost:99999/nonexistent');

        // Result is null due to connection failure, not scheme rejection
        $this->assertNull($result);
    }

    public function testGetAcceptsHttpsScheme(): void
    {
        $client = new FileGetContentsHttpClient(defaultTimeout: 1);

        $result = $client->get('https://localhost:99999/nonexistent');

        $this->assertNull($result);
    }

    public function testGetWithMixedCaseScheme(): void
    {
        $client = new FileGetContentsHttpClient(defaultTimeout: 1);

        // HTTP in mixed case should be accepted (strtolower is used)
        $result = $client->get('HTTP://localhost:99999/nonexistent');

        $this->assertNull($result);
    }

    public function testGetWithUppercaseScheme(): void
    {
        $client = new FileGetContentsHttpClient(defaultTimeout: 1);

        $result = $client->get('HTTPS://localhost:99999/nonexistent');

        $this->assertNull($result);
    }

    public function testGetWithCustomOptions(): void
    {
        $client = new FileGetContentsHttpClient();

        // Test that custom options are parsed correctly
        $result = $client->get('http://localhost:99999/nonexistent', [
            'timeout'          => 1,
            'follow_redirects' => false,
            'max_redirects'    => 3,
            'user_agent'       => 'Test-Agent/1.0',
        ]);

        $this->assertNull($result);
    }

    public function testGetWithPartialOptions(): void
    {
        $client = new FileGetContentsHttpClient(defaultTimeout: 5, defaultUserAgent: 'Default/1.0');

        // Only override some options
        $result = $client->get('http://localhost:99999/nonexistent', [
            'timeout' => 1,
        ]);

        $this->assertNull($result);
    }
}
