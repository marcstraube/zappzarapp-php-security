<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Sanitization\Exception\InvalidUploadException;

#[CoversClass(InvalidUploadException::class)]
final class InvalidUploadExceptionTest extends TestCase
{
    #[Test]
    public function testExtendsRuntimeException(): void
    {
        $this->assertInstanceOf(RuntimeException::class, InvalidUploadException::emptyFile());
    }

    #[Test]
    public function testUploadFailed(): void
    {
        $this->assertSame(
            'Upload failed (code 3): the file was only partially uploaded',
            InvalidUploadException::uploadFailed(3, 'the file was only partially uploaded')->getMessage()
        );
    }

    #[Test]
    public function testUnknownErrorCode(): void
    {
        $this->assertSame(
            'Upload failed with unknown error code 5',
            InvalidUploadException::unknownErrorCode(5)->getMessage()
        );
    }

    #[Test]
    public function testMalformedEntry(): void
    {
        $this->assertSame(
            'Malformed upload entry: "tmp_name" is missing or has the wrong type',
            InvalidUploadException::malformedEntry('tmp_name')->getMessage()
        );
    }

    #[Test]
    public function testNotAnUploadedFile(): void
    {
        $this->assertSame(
            'Temporary file was not created by an HTTP upload',
            InvalidUploadException::notAnUploadedFile()->getMessage()
        );
    }

    #[Test]
    public function testEmptyFile(): void
    {
        $this->assertSame('Uploaded file is empty', InvalidUploadException::emptyFile()->getMessage());
    }

    #[Test]
    public function testTooLarge(): void
    {
        $this->assertSame(
            'Uploaded file is 2048 bytes, the maximum is 1024',
            InvalidUploadException::tooLarge(2048, 1024)->getMessage()
        );
    }

    #[Test]
    public function testMissingClientFilename(): void
    {
        $this->assertSame(
            'Uploaded file has no client filename',
            InvalidUploadException::missingClientFilename()->getMessage()
        );
    }

    #[Test]
    public function testExtensionNotAllowed(): void
    {
        $this->assertSame(
            'No allowed file extension found in "photo.bmp"',
            InvalidUploadException::extensionNotAllowed('photo.bmp')->getMessage()
        );
    }

    #[Test]
    public function testMultipleExtensions(): void
    {
        $this->assertSame(
            'Filename "shell.php.jpg" carries more than one extension',
            InvalidUploadException::multipleExtensions('shell.php.jpg')->getMessage()
        );
    }

    #[Test]
    public function testMimeDetectionFailed(): void
    {
        $this->assertSame(
            'Could not detect the MIME type of the uploaded file',
            InvalidUploadException::mimeDetectionFailed()->getMessage()
        );
    }

    #[Test]
    public function testMimeTypeMismatch(): void
    {
        $this->assertSame(
            'Detected MIME type "text/x-php" is not allowed for extension "jpg"',
            InvalidUploadException::mimeTypeMismatch('jpg', 'text/x-php')->getMessage()
        );
    }
}
