<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Pwned;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Pwned\PwnedCheckerConfig;

#[CoversClass(PwnedCheckerConfig::class)]
final class PwnedCheckerConfigTest extends TestCase
{
    public function testDefaultConfig(): void
    {
        $config = new PwnedCheckerConfig();

        $this->assertSame(PwnedCheckerConfig::DEFAULT_API_URL, $config->apiUrl);
        $this->assertSame(PwnedCheckerConfig::DEFAULT_MIN_OCCURRENCES, $config->minOccurrences);
        $this->assertSame(5, $config->timeout);
        $this->assertFalse($config->throwOnError);
        $this->assertTrue($config->failClosed); // Default is now fail-closed for security
    }

    public function testFailClosedConstant(): void
    {
        $this->assertSame(PHP_INT_MAX, PwnedCheckerConfig::FAIL_CLOSED_COUNT);
    }

    public function testWithFailClosed(): void
    {
        // Start with fail-open to test withFailClosed()
        $config    = (new PwnedCheckerConfig())->withoutFailClosed();
        $newConfig = $config->withFailClosed();

        $this->assertFalse($config->failClosed);
        $this->assertTrue($newConfig->failClosed);
        $this->assertNotSame($config, $newConfig);
    }

    public function testWithoutFailClosed(): void
    {
        $config    = (new PwnedCheckerConfig())->withFailClosed();
        $newConfig = $config->withoutFailClosed();

        $this->assertTrue($config->failClosed);
        $this->assertFalse($newConfig->failClosed);
        $this->assertNotSame($config, $newConfig);
    }

    public function testWithFailClosedPreservesOtherSettings(): void
    {
        $config = new PwnedCheckerConfig(
            apiUrl: 'https://custom.api/',
            minOccurrences: 5,
            timeout: 10,
            throwOnError: true,
            failClosed: false
        );

        $newConfig = $config->withFailClosed();

        $this->assertSame('https://custom.api/', $newConfig->apiUrl);
        $this->assertSame(5, $newConfig->minOccurrences);
        $this->assertSame(10, $newConfig->timeout);
        $this->assertTrue($newConfig->throwOnError);
        $this->assertTrue($newConfig->failClosed);
    }

    public function testWithApiUrlPreservesFailClosed(): void
    {
        $config    = (new PwnedCheckerConfig())->withFailClosed();
        $newConfig = $config->withApiUrl('https://new.api/');

        $this->assertTrue($newConfig->failClosed);
    }

    public function testWithMinOccurrencesPreservesFailClosed(): void
    {
        $config    = (new PwnedCheckerConfig())->withFailClosed();
        $newConfig = $config->withMinOccurrences(10);

        $this->assertTrue($newConfig->failClosed);
    }

    public function testWithTimeoutPreservesFailClosed(): void
    {
        $config    = (new PwnedCheckerConfig())->withFailClosed();
        $newConfig = $config->withTimeout(30);

        $this->assertTrue($newConfig->failClosed);
    }

    public function testWithThrowOnErrorPreservesFailClosed(): void
    {
        $config    = (new PwnedCheckerConfig())->withFailClosed();
        $newConfig = $config->withThrowOnError();

        $this->assertTrue($newConfig->failClosed);
    }

    public function testWithoutThrowOnErrorPreservesFailClosed(): void
    {
        $config    = (new PwnedCheckerConfig())->withFailClosed()->withThrowOnError();
        $newConfig = $config->withoutThrowOnError();

        $this->assertTrue($newConfig->failClosed);
    }

    #[DataProvider('invalidUrlSchemeProvider')]
    public function testConstructorRejectsNonHttpsUrls(string $invalidUrl): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('API URL must use HTTPS scheme');

        new PwnedCheckerConfig(apiUrl: $invalidUrl);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidUrlSchemeProvider(): array
    {
        return [
            'http scheme'   => ['http://api.example.com/'],
            'ftp scheme'    => ['ftp://files.example.com/'],
            'file scheme'   => ['file:///etc/passwd'],
            'no scheme'     => ['//api.example.com/'],
            'gopher scheme' => ['gopher://example.com/'],
        ];
    }

    public function testWithApiUrlRejectsNonHttpsUrls(): void
    {
        $config = new PwnedCheckerConfig();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('API URL must use HTTPS scheme');

        $config->withApiUrl('http://insecure.example.com/');
    }

    public function testWithApiUrlAcceptsHttpsUrls(): void
    {
        $config    = new PwnedCheckerConfig();
        $newConfig = $config->withApiUrl('https://custom.api.com/range/');

        $this->assertSame('https://custom.api.com/range/', $newConfig->apiUrl);
    }

    public function testErrorMessageIncludesActualScheme(): void
    {
        try {
            new PwnedCheckerConfig(apiUrl: 'http://insecure.example.com/');
            $this->fail('Expected InvalidArgumentException');
        } catch (InvalidArgumentException $e) {
            // Error message should include the actual scheme
            $this->assertStringContainsString('http', $e->getMessage());
            $this->assertStringContainsString('HTTPS', $e->getMessage());
        }
    }

    public function testErrorMessageShowsNullForNoScheme(): void
    {
        try {
            new PwnedCheckerConfig(apiUrl: '//no-scheme.example.com/');
            $this->fail('Expected InvalidArgumentException');
        } catch (InvalidArgumentException $e) {
            // Error message should indicate null scheme
            $this->assertStringContainsString('null', $e->getMessage());
        }
    }

    public function testErrorMessageHasCorrectFormat(): void
    {
        try {
            new PwnedCheckerConfig(apiUrl: 'ftp://files.example.com/');
            $this->fail('Expected InvalidArgumentException');
        } catch (InvalidArgumentException $e) {
            // Message should be in format "API URL must use HTTPS scheme. Got: <scheme>"
            // The "API URL" part should come first, not the scheme
            $message = $e->getMessage();
            $this->assertStringStartsWith('API URL must use HTTPS scheme', $message);
        }
    }

    public function testProductionFactoryReturnsFailClosedConfig(): void
    {
        $config = PwnedCheckerConfig::production();

        $this->assertTrue($config->failClosed);
        $this->assertFalse($config->throwOnError);
        $this->assertSame(PwnedCheckerConfig::DEFAULT_API_URL, $config->apiUrl);
        $this->assertSame(PwnedCheckerConfig::DEFAULT_MIN_OCCURRENCES, $config->minOccurrences);
        $this->assertSame(5, $config->timeout);
    }

    public function testDevelopmentFactoryReturnsFailOpenConfig(): void
    {
        $config = PwnedCheckerConfig::development();

        $this->assertFalse($config->failClosed);
        $this->assertFalse($config->throwOnError);
        $this->assertSame(PwnedCheckerConfig::DEFAULT_API_URL, $config->apiUrl);
        $this->assertSame(PwnedCheckerConfig::DEFAULT_MIN_OCCURRENCES, $config->minOccurrences);
        $this->assertSame(5, $config->timeout);
    }
}
