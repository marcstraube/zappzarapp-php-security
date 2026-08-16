<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Upload\FinfoMimeTypeDetector;

#[CoversClass(FinfoMimeTypeDetector::class)]
final class FinfoMimeTypeDetectorTest extends TestCase
{
    private FinfoMimeTypeDetector $detector;

    /**
     * @var list<string>
     */
    private array $temporaryFiles = [];

    protected function setUp(): void
    {
        $this->detector = new FinfoMimeTypeDetector();
    }

    protected function tearDown(): void
    {
        foreach ($this->temporaryFiles as $path) {
            if (is_file($path)) {
                unlink($path);
            }
        }

        $this->temporaryFiles = [];
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function sampleProvider(): array
    {
        return [
            'png'        => [UploadFixtures::PNG, 'image/png'],
            'gif'        => [UploadFixtures::GIF, 'image/gif'],
            'jpeg'       => [UploadFixtures::JPEG, 'image/jpeg'],
            'pdf'        => [UploadFixtures::PDF, 'application/pdf'],
            'plain text' => [UploadFixtures::TEXT, 'text/plain'],
            'php script' => [UploadFixtures::PHP, 'text/x-php'],
        ];
    }

    #[DataProvider('sampleProvider')]
    #[Test]
    public function testDetectFromBuffer(string $content, string $expected): void
    {
        $this->assertSame($expected, $this->detector->detectFromBuffer($content));
    }

    #[DataProvider('sampleProvider')]
    #[Test]
    public function testDetectFromFile(string $content, string $expected): void
    {
        $this->assertSame($expected, $this->detector->detectFromFile($this->writeTemporaryFile($content)));
    }

    #[Test]
    public function testDetectionIgnoresTheExtension(): void
    {
        // The classic attack: a PHP script named like an image
        $path = $this->writeTemporaryFile(UploadFixtures::PHP);

        $this->assertSame('text/x-php', $this->detector->detectFromFile($path));
        $this->assertNotSame('image/jpeg', $this->detector->detectFromFile($path));
    }

    #[Test]
    public function testMissingFileReturnsNull(): void
    {
        $this->assertNull($this->detector->detectFromFile('/nonexistent/upload.tmp'));
    }

    #[Test]
    public function testDirectoryReturnsNull(): void
    {
        $this->assertNull($this->detector->detectFromFile(sys_get_temp_dir()));
    }

    #[Test]
    public function testEmptyBufferIsReported(): void
    {
        $this->assertSame('application/x-empty', $this->detector->detectFromBuffer(''));
    }

    private function writeTemporaryFile(string $content): string
    {
        $path = tempnam(sys_get_temp_dir(), 'zzp-finfo-');
        $this->assertIsString($path);

        $this->temporaryFiles[] = $path;

        file_put_contents($path, $content);

        return $path;
    }
}
