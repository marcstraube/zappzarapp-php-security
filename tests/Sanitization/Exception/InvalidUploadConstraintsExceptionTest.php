<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Exception\InvalidUploadConstraintsException;

#[CoversClass(InvalidUploadConstraintsException::class)]
final class InvalidUploadConstraintsExceptionTest extends TestCase
{
    #[Test]
    public function testExtendsInvalidArgumentException(): void
    {
        $this->assertInstanceOf(
            InvalidArgumentException::class,
            InvalidUploadConstraintsException::emptyAllowList()
        );
    }

    #[Test]
    public function testEmptyAllowList(): void
    {
        $this->assertSame(
            'Upload constraints require a non-empty extension allow-list',
            InvalidUploadConstraintsException::emptyAllowList()->getMessage()
        );
    }

    #[Test]
    public function testInvalidExtension(): void
    {
        $this->assertSame(
            'Invalid allow-list extension "tar-gz": expected alphanumeric segments separated by dots',
            InvalidUploadConstraintsException::invalidExtension('tar-gz')->getMessage()
        );
    }

    #[Test]
    public function testEmptyMimeTypeList(): void
    {
        $this->assertSame(
            'Extension "pdf" must be mapped to at least one MIME type',
            InvalidUploadConstraintsException::emptyMimeTypeList('pdf')->getMessage()
        );
    }

    #[Test]
    public function testInvalidMimeType(): void
    {
        $this->assertSame(
            'Invalid MIME type "nonsense": expected "type/subtype"',
            InvalidUploadConstraintsException::invalidMimeType('nonsense')->getMessage()
        );
    }

    #[Test]
    public function testInvalidMaxSize(): void
    {
        $this->assertSame(
            'Maximum upload size must be at least 1 byte, got -5',
            InvalidUploadConstraintsException::invalidMaxSize(-5)->getMessage()
        );
    }

    #[Test]
    public function testInvalidMaxFilenameLength(): void
    {
        $this->assertSame(
            'Maximum filename length must be at least 1 byte, got 0',
            InvalidUploadConstraintsException::invalidMaxFilenameLength(0)->getMessage()
        );
    }
}
