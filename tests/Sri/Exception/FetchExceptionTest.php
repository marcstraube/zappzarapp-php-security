<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Sri\Exception\FetchException;

#[CoversClass(FetchException::class)]
final class FetchExceptionTest extends TestCase
{
    public function testExtendsRuntimeException(): void
    {
        $exception = FetchException::failed('https://example.com', 'Connection refused');

        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    public function testFailedFactoryMethod(): void
    {
        $url       = 'https://cdn.example.com/lib.js';
        $reason    = 'Connection timeout';
        $exception = FetchException::failed($url, $reason);

        $this->assertStringContainsString('Failed to fetch resource from', $exception->getMessage());
        $this->assertStringContainsString($url, $exception->getMessage());
        $this->assertStringContainsString($reason, $exception->getMessage());
    }

    public function testTimeoutFactoryMethod(): void
    {
        $url       = 'https://slow-server.example.com/large-file.js';
        $exception = FetchException::timeout($url);

        $this->assertStringContainsString('Timeout while fetching resource from', $exception->getMessage());
        $this->assertStringContainsString($url, $exception->getMessage());
    }

    public function testInvalidUrlFactoryMethod(): void
    {
        $url       = 'not-a-valid-url';
        $exception = FetchException::invalidUrl($url);

        $this->assertStringContainsString('Invalid URL:', $exception->getMessage());
        $this->assertStringContainsString($url, $exception->getMessage());
    }

    public function testFailedWithSpecialCharactersInUrl(): void
    {
        $url       = 'https://example.com/path?param=value&other=123';
        $reason    = 'HTTP 404 Not Found';
        $exception = FetchException::failed($url, $reason);

        $this->assertStringContainsString($url, $exception->getMessage());
        $this->assertStringContainsString($reason, $exception->getMessage());
    }

    public function testFailedWithEmptyReason(): void
    {
        $url       = 'https://example.com/file.js';
        $exception = FetchException::failed($url, '');

        $this->assertStringContainsString($url, $exception->getMessage());
    }

    public function testTimeoutWithLongUrl(): void
    {
        $url       = 'https://example.com/' . str_repeat('a', 200);
        $exception = FetchException::timeout($url);

        $this->assertStringContainsString($url, $exception->getMessage());
    }

    public function testInvalidUrlWithEmptyString(): void
    {
        $exception = FetchException::invalidUrl('');

        $this->assertStringContainsString('Invalid URL:', $exception->getMessage());
    }

    public function testInvalidUrlWithMalformedUrl(): void
    {
        $malformedUrls = [
            'ftp://example.com/file',
            'file:///etc/passwd',
            'javascript:alert(1)',
            '//example.com/path',
        ];

        foreach ($malformedUrls as $url) {
            $exception = FetchException::invalidUrl($url);

            $this->assertStringContainsString($url, $exception->getMessage());
        }
    }

    public function testFailedWithNetworkErrors(): void
    {
        $networkErrors = [
            'Connection refused',
            'DNS resolution failed',
            'SSL certificate verification failed',
            'Network unreachable',
            'Too many redirects',
        ];

        foreach ($networkErrors as $error) {
            $exception = FetchException::failed('https://example.com', $error);

            $this->assertStringContainsString($error, $exception->getMessage());
        }
    }

    public function testFailedWithHttpStatusErrors(): void
    {
        $httpErrors = [
            'HTTP 400 Bad Request',
            'HTTP 401 Unauthorized',
            'HTTP 403 Forbidden',
            'HTTP 404 Not Found',
            'HTTP 500 Internal Server Error',
            'HTTP 502 Bad Gateway',
            'HTTP 503 Service Unavailable',
        ];

        foreach ($httpErrors as $error) {
            $exception = FetchException::failed('https://api.example.com/resource', $error);

            $this->assertStringContainsString($error, $exception->getMessage());
        }
    }
}
