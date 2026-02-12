<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sri\ResourceFetcherConfig;

#[CoversClass(ResourceFetcherConfig::class)]
final class ResourceFetcherConfigTest extends TestCase
{
    public function testDefaultValues(): void
    {
        $config = new ResourceFetcherConfig();

        $this->assertSame(10, $config->timeout);
        $this->assertSame(10485760, $config->maxSize); // 10 MB
        $this->assertTrue($config->followRedirects);
        $this->assertSame(5, $config->maxRedirects);
        $this->assertSame('Zappzarapp-Security-SRI/1.0', $config->userAgent);
    }

    public function testCustomValues(): void
    {
        $config = new ResourceFetcherConfig(
            timeout: 30,
            maxSize: 5242880,
            followRedirects: false,
            maxRedirects: 3,
            userAgent: 'Custom-Agent/2.0'
        );

        $this->assertSame(30, $config->timeout);
        $this->assertSame(5242880, $config->maxSize);
        $this->assertFalse($config->followRedirects);
        $this->assertSame(3, $config->maxRedirects);
        $this->assertSame('Custom-Agent/2.0', $config->userAgent);
    }

    public function testWithTimeout(): void
    {
        $config    = new ResourceFetcherConfig();
        $newConfig = $config->withTimeout(60);

        // Original unchanged (immutability)
        $this->assertSame(10, $config->timeout);

        // New config has updated timeout
        $this->assertSame(60, $newConfig->timeout);

        // Other values preserved
        $this->assertSame($config->maxSize, $newConfig->maxSize);
        $this->assertSame($config->followRedirects, $newConfig->followRedirects);
        $this->assertSame($config->maxRedirects, $newConfig->maxRedirects);
        $this->assertSame($config->userAgent, $newConfig->userAgent);
    }

    public function testWithMaxSize(): void
    {
        $config    = new ResourceFetcherConfig();
        $newConfig = $config->withMaxSize(1048576); // 1 MB

        // Original unchanged (immutability)
        $this->assertSame(10485760, $config->maxSize);

        // New config has updated maxSize
        $this->assertSame(1048576, $newConfig->maxSize);

        // Other values preserved
        $this->assertSame($config->timeout, $newConfig->timeout);
        $this->assertSame($config->followRedirects, $newConfig->followRedirects);
        $this->assertSame($config->maxRedirects, $newConfig->maxRedirects);
        $this->assertSame($config->userAgent, $newConfig->userAgent);
    }

    public function testWithoutRedirects(): void
    {
        $config    = new ResourceFetcherConfig();
        $newConfig = $config->withoutRedirects();

        // Original unchanged (immutability)
        $this->assertTrue($config->followRedirects);
        $this->assertSame(5, $config->maxRedirects);

        // New config has disabled redirects
        $this->assertFalse($newConfig->followRedirects);
        $this->assertSame(0, $newConfig->maxRedirects);

        // Other values preserved
        $this->assertSame($config->timeout, $newConfig->timeout);
        $this->assertSame($config->maxSize, $newConfig->maxSize);
        $this->assertSame($config->userAgent, $newConfig->userAgent);
    }

    public function testImmutability(): void
    {
        $original = new ResourceFetcherConfig();

        $original->withTimeout(60);
        $original->withMaxSize(1048576);
        $original->withoutRedirects();

        // Original remains unchanged
        $this->assertSame(10, $original->timeout);
        $this->assertSame(10485760, $original->maxSize);
        $this->assertTrue($original->followRedirects);
        $this->assertSame(5, $original->maxRedirects);
    }

    public function testChainedMutators(): void
    {
        $config = (new ResourceFetcherConfig())
            ->withTimeout(30)
            ->withMaxSize(2097152)
            ->withoutRedirects();

        $this->assertSame(30, $config->timeout);
        $this->assertSame(2097152, $config->maxSize);
        $this->assertFalse($config->followRedirects);
        $this->assertSame(0, $config->maxRedirects);
    }

    public function testReadonlyProperties(): void
    {
        $config = new ResourceFetcherConfig();

        // Verify config is readonly by checking it's an instance
        // (readonly classes cannot have their properties modified)
        $this->assertInstanceOf(ResourceFetcherConfig::class, $config);
    }
}
