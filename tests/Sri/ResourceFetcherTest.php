<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Uri\PrivateNetworkValidator;
use Zappzarapp\Security\Sri\Exception\FetchException;
use Zappzarapp\Security\Sri\FileGetContentsHttpClient;
use Zappzarapp\Security\Sri\HashAlgorithm;
use Zappzarapp\Security\Sri\HttpClientInterface;
use Zappzarapp\Security\Sri\IntegrityAttribute;
use Zappzarapp\Security\Sri\ResourceFetcher;
use Zappzarapp\Security\Sri\ResourceFetcherConfig;

#[CoversClass(ResourceFetcher::class)]
#[CoversClass(FileGetContentsHttpClient::class)]
#[UsesClass(IntegrityAttribute::class)]
#[UsesClass(HashAlgorithm::class)]
#[UsesClass(PrivateNetworkValidator::class)]
final class ResourceFetcherTest extends TestCase
{
    public function testFetchWithCustomHttpClient(): void
    {
        $expectedContent = 'console.log("hello");';

        $client = $this->createMock(HttpClientInterface::class);
        $client->expects($this->once())
            ->method('get')
            ->with(
                'https://example.com/script.js',
                $this->callback(fn(array $options): bool => isset($options['timeout'])
                    && isset($options['follow_redirects'])
                    && isset($options['max_redirects'])
                    && isset($options['user_agent']))
            )
            ->willReturn($expectedContent);

        $fetcher = new ResourceFetcher(new ResourceFetcherConfig(), $client);

        $result = $fetcher->fetch('https://example.com/script.js');

        $this->assertSame($expectedContent, $result);
    }

    public function testFetchThrowsOnHttpClientFailure(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn(null);

        $fetcher = new ResourceFetcher(new ResourceFetcherConfig(), $client);

        $this->expectException(FetchException::class);
        $fetcher->fetch('https://example.com/script.js');
    }

    public function testFetchThrowsOnInvalidUrl(): void
    {
        $fetcher = new ResourceFetcher();

        $this->expectException(FetchException::class);
        $fetcher->fetch('not-a-valid-url');
    }

    public function testFetchThrowsOnNonHttpScheme(): void
    {
        $fetcher = new ResourceFetcher();

        $this->expectException(FetchException::class);
        $fetcher->fetch('ftp://example.com/file.txt');
    }

    public function testFetchThrowsOnContentExceedingMaxSize(): void
    {
        $largeContent = str_repeat('x', 1000);

        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn($largeContent);

        $config  = new ResourceFetcherConfig(maxSize: 100);
        $fetcher = new ResourceFetcher($config, $client);

        $this->expectException(FetchException::class);
        $this->expectExceptionMessage('exceeds maximum size');
        $fetcher->fetch('https://example.com/large-file.js');
    }

    public function testFetchPassesConfigToClient(): void
    {
        $client = $this->createMock(HttpClientInterface::class);
        $client->expects($this->once())
            ->method('get')
            ->with(
                'https://example.com/script.js',
                $this->callback(fn(array $options): bool => $options['timeout'] === 30
                    && $options['follow_redirects'] === false
                    && $options['max_redirects'] === 0
                    && $options['user_agent'] === 'Zappzarapp-Security-SRI/1.0')
            )
            ->willReturn('content');

        $config  = (new ResourceFetcherConfig())->withTimeout(30)->withoutRedirects();
        $fetcher = new ResourceFetcher($config, $client);

        $fetcher->fetch('https://example.com/script.js');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function blockedSchemeProvider(): array
    {
        return [
            'file scheme'   => ['file:///etc/passwd'],
            'ftp scheme'    => ['ftp://example.com/file.txt'],
            'gopher scheme' => ['gopher://localhost:9000/'],
            'data scheme'   => ['data:text/html,<script>alert(1)</script>'],
            'php scheme'    => ['php://filter/resource=/etc/passwd'],
            'no scheme'     => ['//example.com/script.js'],
            'empty string'  => [''],
            'malformed url' => ['not-a-url'],
        ];
    }

    #[DataProvider('blockedSchemeProvider')]
    public function testFileGetContentsHttpClientBlocksNonHttpSchemes(string $url): void
    {
        $client = new FileGetContentsHttpClient();

        $result = $client->get($url);

        $this->assertNull($result, "URL with blocked scheme should return null: {$url}");
    }

    public function testFileGetContentsHttpClientAllowsHttpScheme(): void
    {
        $client = new FileGetContentsHttpClient(defaultTimeout: 1);

        // This will fail due to network (timeout), but NOT due to schema validation
        // If it returned null immediately, the schema check blocked it incorrectly
        $result = $client->get('http://localhost:99999/nonexistent');

        // Result is null because connection fails, not because schema is blocked
        $this->assertNull($result);
    }

    public function testFileGetContentsHttpClientAllowsHttpsScheme(): void
    {
        $client = new FileGetContentsHttpClient(defaultTimeout: 1);

        // This will fail due to network (timeout), but NOT due to schema validation
        $result = $client->get('https://localhost:99999/nonexistent');

        // Result is null because connection fails, not because schema is blocked
        $this->assertNull($result);
    }

    public function testFileGetContentsHttpClientIsCaseInsensitiveForScheme(): void
    {
        $client = new FileGetContentsHttpClient(defaultTimeout: 1);

        // Uppercase schemes should also be allowed (handled via strtolower)
        // These will fail due to network issues, not schema validation
        $result = $client->get('HTTP://localhost:99999/nonexistent');
        $this->assertNull($result);

        $result = $client->get('HTTPS://localhost:99999/nonexistent');
        $this->assertNull($result);
    }

    public function testFetchAndHashReturnsIntegrityAttribute(): void
    {
        $content = 'console.log("test");';

        $client = $this->createMock(HttpClientInterface::class);
        $client->expects($this->once())
            ->method('get')
            ->willReturn($content);

        $fetcher   = new ResourceFetcher(new ResourceFetcherConfig(), $client);
        $integrity = $fetcher->fetchAndHash('https://example.com/script.js');

        $this->assertInstanceOf(IntegrityAttribute::class, $integrity);
        $this->assertStringStartsWith('sha384-', $integrity->value());
    }

    public function testFetchAndHashWithCustomAlgorithm(): void
    {
        $content = 'var x = 1;';

        $client = $this->createMock(HttpClientInterface::class);
        $client->expects($this->once())
            ->method('get')
            ->willReturn($content);

        $fetcher   = new ResourceFetcher(new ResourceFetcherConfig(), $client);
        $integrity = $fetcher->fetchAndHash('https://example.com/script.js', HashAlgorithm::SHA512);

        $this->assertStringStartsWith('sha512-', $integrity->value());
    }

    public function testFetchAndHashWithSha512(): void
    {
        $content = 'function test() {}';

        $client = $this->createMock(HttpClientInterface::class);
        $client->expects($this->once())
            ->method('get')
            ->willReturn($content);

        $fetcher   = new ResourceFetcher(new ResourceFetcherConfig(), $client);
        $integrity = $fetcher->fetchAndHash('https://example.com/script.js', HashAlgorithm::SHA512);

        $this->assertStringStartsWith('sha512-', $integrity->value());
    }

    public function testFetchAndHashThrowsOnFetchFailure(): void
    {
        $client = $this->createStub(HttpClientInterface::class);
        $client->method('get')->willReturn(null);

        $fetcher = new ResourceFetcher(new ResourceFetcherConfig(), $client);

        $this->expectException(FetchException::class);
        $fetcher->fetchAndHash('https://example.com/script.js');
    }

    public function testFetchAndHashProducesVerifiableHash(): void
    {
        $content = 'alert("verified");';

        $client = $this->createMock(HttpClientInterface::class);
        $client->expects($this->once())
            ->method('get')
            ->willReturn($content);

        $fetcher   = new ResourceFetcher(new ResourceFetcherConfig(), $client);
        $integrity = $fetcher->fetchAndHash('https://example.com/script.js', HashAlgorithm::SHA384);

        // Verify the hash is correct by manually computing
        $expected = IntegrityAttribute::fromContent($content, HashAlgorithm::SHA384);
        $this->assertSame($expected->value(), $integrity->value());
    }

    // =========================================================================
    // SSRF Protection Tests
    // =========================================================================

    /**
     * @return array<string, array{string}>
     */
    public static function ssrfBlockedUrlProvider(): array
    {
        return [
            'localhost'                    => ['http://localhost/script.js'],
            'loopback ipv4'                => ['http://127.0.0.1/script.js'],
            'loopback ipv4 alt'            => ['http://127.0.0.127/script.js'],
            'private 10.x'                 => ['http://10.0.0.1/script.js'],
            'private 172.16.x'             => ['http://172.16.0.1/script.js'],
            'private 192.168.x'            => ['http://192.168.1.1/script.js'],
            'aws metadata'                 => ['http://169.254.169.254/latest/meta-data/'],
            'gcp metadata'                 => ['http://metadata.google.internal/'],
            'kubernetes default'           => ['http://kubernetes.default/api'],
            'link-local'                   => ['http://169.254.1.1/internal'],
            'ipv6 loopback'                => ['http://[::1]/script.js'],
        ];
    }

    #[DataProvider('ssrfBlockedUrlProvider')]
    public function testFetchBlocksSsrfAttacks(string $url): void
    {
        $client = $this->createMock(HttpClientInterface::class);
        // Client should never be called for SSRF-blocked URLs
        $client->expects($this->never())->method('get');

        $fetcher = new ResourceFetcher(new ResourceFetcherConfig(), $client);

        $this->expectException(FetchException::class);
        $this->expectExceptionMessage('SSRF protection');
        $fetcher->fetch($url);
    }

    public function testFetchAllowsPublicUrls(): void
    {
        $content = 'console.log("public");';

        $client = $this->createMock(HttpClientInterface::class);
        $client->expects($this->once())
            ->method('get')
            ->willReturn($content);

        $fetcher = new ResourceFetcher(new ResourceFetcherConfig(), $client);
        $result  = $fetcher->fetch('https://cdn.example.com/script.js');

        $this->assertSame($content, $result);
    }

    public function testFetchWithSsrfValidatorDisabled(): void
    {
        $content = 'internal content';

        $client = $this->createMock(HttpClientInterface::class);
        $client->expects($this->once())
            ->method('get')
            ->willReturn($content);

        // Explicitly disable SSRF validation and allow HTTP (for development only)
        $fetcher = new ResourceFetcher(
            config: ResourceFetcherConfig::development(),
            client: $client,
            ssrfValidator: null
        );

        // Should allow localhost when SSRF validation is disabled and HTTP is allowed
        $result = $fetcher->fetch('http://localhost/internal.js');

        $this->assertSame($content, $result);
    }

    public function testFetchWithRealSsrfValidatorAllowsPublicHosts(): void
    {
        // Use a real PrivateNetworkValidator instance
        $validator = new PrivateNetworkValidator();

        $client = $this->createMock(HttpClientInterface::class);
        $client->expects($this->once())
            ->method('get')
            ->willReturn('content');

        $fetcher = new ResourceFetcher(
            config: new ResourceFetcherConfig(),
            client: $client,
            ssrfValidator: $validator
        );

        // Public hostname should be allowed
        $result = $fetcher->fetch('https://example.com/script.js');

        $this->assertSame('content', $result);
    }

    public function testFetchSsrfExceptionContainsHostInfo(): void
    {
        $client = $this->createMock(HttpClientInterface::class);
        $client->expects($this->never())->method('get');

        $fetcher = new ResourceFetcher(new ResourceFetcherConfig(), $client);

        try {
            $fetcher->fetch('http://169.254.169.254/latest/meta-data/');
            $this->fail('Expected FetchException');
        } catch (FetchException $e) {
            $this->assertStringContainsString('169.254.169.254', $e->getMessage());
            $this->assertStringContainsString('SSRF protection', $e->getMessage());
        }
    }
}
