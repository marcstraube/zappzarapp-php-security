<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw upload exceptions */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Exception\InvalidFilenameException;
use Zappzarapp\Security\Sanitization\Exception\InvalidUploadException;
use Zappzarapp\Security\Sanitization\Upload\UploadConstraints;
use Zappzarapp\Security\Sanitization\Upload\UploadValidator;

#[CoversClass(UploadValidator::class)]
final class UploadValidatorPsr7Test extends TestCase
{
    // --- Accepted uploads ---

    #[Test]
    public function testValidatesAPsr7Upload(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), 'photo.png');

        $upload = $this->imageValidator()->validateUploadedFile($file);

        $this->assertSame('photo.png', $upload->filename);
        $this->assertSame('png', $upload->extension);
        $this->assertSame('image/png', $upload->mimeType);
        $this->assertSame(strlen(UploadFixtures::PNG), $upload->sizeBytes);
    }

    #[Test]
    public function testTheFilenameIsSanitized(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), '../../etc/photo (1).png');

        $this->assertSame('photo__1_.png', $this->imageValidator()->validateUploadedFile($file)->filename);
    }

    #[Test]
    public function testClientMediaTypeIsIgnored(): void
    {
        $file = new FakeUploadedFile(
            new FakeStream(UploadFixtures::PHP),
            'notes.txt',
            clientMediaType: 'text/plain'
        );

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Detected MIME type "text/x-php" is not allowed for extension "txt"');

        $this->textValidator()->validateUploadedFile($file);
    }

    #[Test]
    public function testDoubleExtensionIsRejected(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), 'shell.php.png');

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('carries more than one extension');

        $this->imageValidator()->validateUploadedFile($file);
    }

    #[Test]
    public function testHostileFilenameIsRejected(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), "photo.png\0.php");

        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('NUL byte');

        $this->imageValidator()->validateUploadedFile($file);
    }

    // --- Upload errors ---

    /**
     * @return array<string, array{int, string}>
     */
    public static function failedUploadProvider(): array
    {
        return [
            'ini size' => [UPLOAD_ERR_INI_SIZE, 'the file exceeds the upload_max_filesize directive'],
            'partial'  => [UPLOAD_ERR_PARTIAL, 'the file was only partially uploaded'],
            'no file'  => [UPLOAD_ERR_NO_FILE, 'no file was uploaded'],
        ];
    }

    #[DataProvider('failedUploadProvider')]
    #[Test]
    public function testFailedUploadIsRejected(int $error, string $reason): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), 'photo.png', $error);

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage($reason);

        $this->imageValidator()->validateUploadedFile($file);
    }

    #[Test]
    public function testUnknownErrorCodeIsRejected(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), 'photo.png', 5);

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('unknown error code 5');

        $this->imageValidator()->validateUploadedFile($file);
    }

    #[Test]
    public function testMissingClientFilenameIsRejected(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), null);

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('no client filename');

        $this->imageValidator()->validateUploadedFile($file);
    }

    // --- Stream handling ---

    #[Test]
    public function testEmptyStreamIsRejected(): void
    {
        $file = new FakeUploadedFile(new FakeStream(''), 'photo.png');

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Uploaded file is empty');

        $this->imageValidator()->validateUploadedFile($file);
    }

    #[Test]
    public function testStreamAtTheSizeLimitIsAccepted(): void
    {
        $file = new FakeUploadedFile(new FakeStream('hello worl', 5), 'notes.txt');

        $upload = $this->textValidator(10)->validateUploadedFile($file);

        $this->assertSame(10, $upload->sizeBytes);
        $this->assertSame('text/plain', $upload->mimeType);
    }

    #[Test]
    public function testStreamOneByteOverTheLimitIsRejected(): void
    {
        // Chunked so the buffer lands exactly on the limit before the
        // final read, which is what the loop boundary has to survive
        $file = new FakeUploadedFile(new FakeStream('hello world', 5), 'notes.txt');

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Uploaded file is 11 bytes, the maximum is 10');

        $this->textValidator(10)->validateUploadedFile($file);
    }

    #[Test]
    public function testReadingStopsAsSoonAsTheLimitIsExceeded(): void
    {
        // 30 bytes against a 10 byte limit, read in 5 byte chunks: the
        // loop must stop at the first chunk that crosses the limit
        // instead of buffering the whole stream
        $file = new FakeUploadedFile(new FakeStream(str_repeat('abcde', 6), 5), 'notes.txt');

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Uploaded file is 15 bytes, the maximum is 10');

        $this->textValidator(10)->validateUploadedFile($file);
    }

    #[Test]
    public function testFilenameRejectionIsLogged(): void
    {
        $logger    = new RecordingLogger();
        $validator = new UploadValidator(UploadConstraints::images(), $logger);
        $file      = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), "photo\0.png");

        $this->assertFalse($validator->isValidUploadedFile($file));
        $this->assertCount(1, $logger->warnings);
        $this->assertSame('Filename contains a NUL byte', $logger->warnings[0]['context']['reason']);
    }

    #[Test]
    public function testReportedSizeIsIgnored(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), 'photo.png', size: 1);

        $this->assertSame(
            strlen(UploadFixtures::PNG),
            $this->imageValidator()->validateUploadedFile($file)->sizeBytes
        );
    }

    #[Test]
    public function testStreamWithoutAReportedSizeIsStillValidated(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG, reportSize: false), 'photo.png');

        $this->assertSame(
            strlen(UploadFixtures::PNG),
            $this->imageValidator()->validateUploadedFile($file)->sizeBytes
        );
    }

    #[Test]
    public function testAlreadyConsumedSeekableStreamIsRewound(): void
    {
        $stream = new FakeStream(UploadFixtures::PNG);
        $stream->read(6);

        $file = new FakeUploadedFile($stream, 'photo.png');

        $upload = $this->imageValidator()->validateUploadedFile($file);

        $this->assertSame(strlen(UploadFixtures::PNG), $upload->sizeBytes);
        $this->assertSame('image/png', $upload->mimeType);
    }

    #[Test]
    public function testNonSeekableStreamIsReadWithoutRewinding(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG, seekable: false), 'photo.png');

        $upload = $this->imageValidator()->validateUploadedFile($file);

        $this->assertSame(strlen(UploadFixtures::PNG), $upload->sizeBytes);
    }

    #[Test]
    public function testStreamThatNeverReportsEofIsStillBounded(): void
    {
        // Some stream implementations only report EOF after a failed
        // read, so an empty chunk has to end the loop as well
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG, 5, neverEof: true), 'photo.png');

        $upload = $this->imageValidator()->validateUploadedFile($file);

        $this->assertSame(strlen(UploadFixtures::PNG), $upload->sizeBytes);
    }

    #[Test]
    public function testEmptyStreamThatNeverReportsEofIsRejected(): void
    {
        $file = new FakeUploadedFile(new FakeStream('', 5, neverEof: true), 'photo.png');

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Uploaded file is empty');

        $this->imageValidator()->validateUploadedFile($file);
    }

    // --- Logging and the non-throwing API ---

    #[Test]
    public function testRejectionIsLogged(): void
    {
        $logger    = new RecordingLogger();
        $validator = new UploadValidator(UploadConstraints::images(), $logger);
        $file      = new FakeUploadedFile(new FakeStream(UploadFixtures::PHP), 'shell.png');

        $this->assertFalse($validator->isValidUploadedFile($file));
        $this->assertCount(1, $logger->warnings);
        $this->assertSame('File upload rejected', $logger->warnings[0]['message']);
    }

    #[Test]
    public function testIsValidUploadedFileReturnsTrue(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), 'photo.png');

        $this->assertTrue($this->imageValidator()->isValidUploadedFile($file));
    }

    #[Test]
    public function testIsValidUploadedFileReturnsFalseOnBadFilename(): void
    {
        $file = new FakeUploadedFile(new FakeStream(UploadFixtures::PNG), "photo\0.png");

        $this->assertFalse($this->imageValidator()->isValidUploadedFile($file));
    }

    // --- Helpers ---

    private function imageValidator(): UploadValidator
    {
        return new UploadValidator(UploadConstraints::images());
    }

    private function textValidator(int $maxSizeBytes = UploadConstraints::DEFAULT_MAX_SIZE_BYTES): UploadValidator
    {
        return new UploadValidator(new UploadConstraints(['txt' => ['text/plain']], $maxSizeBytes));
    }
}
