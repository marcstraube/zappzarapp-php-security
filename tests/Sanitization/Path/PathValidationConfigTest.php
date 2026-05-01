<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Path;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Path\PathValidationConfig;

#[CoversClass(PathValidationConfig::class)]
final class PathValidationConfigTest extends TestCase
{
    #[Test]
    public function testDefaultValues(): void
    {
        $config = new PathValidationConfig();

        $this->assertNull($config->basePath);
        $this->assertFalse($config->allowDotFiles);
        $this->assertFalse($config->allowSymlinks);
        $this->assertTrue($config->normalizePath);
        $this->assertSame([], $config->blockedExtensions);
    }

    #[Test]
    public function testCustomValues(): void
    {
        $config = new PathValidationConfig(
            basePath: '/var/www',
            allowDotFiles: true,
            allowSymlinks: true,
            normalizePath: false,
            blockedExtensions: ['php', 'exe']
        );

        $this->assertSame('/var/www', $config->basePath);
        $this->assertTrue($config->allowDotFiles);
        $this->assertTrue($config->allowSymlinks);
        $this->assertFalse($config->normalizePath);
        $this->assertSame(['php', 'exe'], $config->blockedExtensions);
    }

    #[Test]
    public function testWithBasePath(): void
    {
        $config    = new PathValidationConfig();
        $newConfig = $config->withBasePath('/uploads');

        $this->assertNull($config->basePath);
        $this->assertSame('/uploads', $newConfig->basePath);
        $this->assertNotSame($config, $newConfig);
    }

    #[Test]
    public function testWithDotFiles(): void
    {
        $config    = new PathValidationConfig();
        $newConfig = $config->withDotFiles();

        $this->assertFalse($config->allowDotFiles);
        $this->assertTrue($newConfig->allowDotFiles);
    }

    #[Test]
    public function testWithSymlinks(): void
    {
        $config    = new PathValidationConfig();
        $newConfig = $config->withSymlinks();

        $this->assertFalse($config->allowSymlinks);
        $this->assertTrue($newConfig->allowSymlinks);
    }

    #[Test]
    public function testWithBlockedExtensions(): void
    {
        $config    = new PathValidationConfig();
        $newConfig = $config->withBlockedExtensions(['php', 'exe']);

        $this->assertSame([], $config->blockedExtensions);
        $this->assertSame(['php', 'exe'], $newConfig->blockedExtensions);
    }

    #[Test]
    public function testStrictFactory(): void
    {
        $config = PathValidationConfig::strict('/uploads');

        $this->assertSame('/uploads', $config->basePath);
        $this->assertFalse($config->allowDotFiles);
        $this->assertFalse($config->allowSymlinks);
        $this->assertTrue($config->normalizePath);
        $this->assertNotEmpty($config->blockedExtensions);
        $this->assertContains('php', $config->blockedExtensions);
        $this->assertContains('phar', $config->blockedExtensions);
    }

    #[Test]
    public function testImmutability(): void
    {
        $original = new PathValidationConfig();

        $original->withBasePath('/uploads');
        $original->withDotFiles();
        $original->withSymlinks();
        $original->withBlockedExtensions(['php']);

        $this->assertNull($original->basePath);
        $this->assertFalse($original->allowDotFiles);
        $this->assertFalse($original->allowSymlinks);
        $this->assertSame([], $original->blockedExtensions);
    }
}
