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
use Zappzarapp\Security\Sanitization\Upload\FinfoMimeTypeDetector;
use Zappzarapp\Security\Sanitization\Upload\UploadConstraints;
use Zappzarapp\Security\Sanitization\Upload\UploadValidator;

#[CoversClass(UploadValidator::class)]
final class UploadValidatorTest extends TestCase
{
    /**
     * @var list<string>
     */
    private array $temporaryFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->temporaryFiles as $path) {
            if (is_file($path)) {
                unlink($path);
            }
        }

        $this->temporaryFiles = [];
    }

    // --- Accepted uploads ---

    #[Test]
    public function testValidatesAnImageUpload(): void
    {
        $validator = $this->validator();

        $upload = $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png'));

        $this->assertSame('photo.png', $upload->filename);
        $this->assertSame('png', $upload->extension);
        $this->assertSame('image/png', $upload->mimeType);
        $this->assertSame(strlen(UploadFixtures::PNG), $upload->sizeBytes);
    }

    #[Test]
    public function testFilenameIsSanitized(): void
    {
        $validator = $this->validator();

        $upload = $validator->validateNativeUpload(
            $this->entry(UploadFixtures::PNG, '../../var/uploads/photo (1).png')
        );

        $this->assertSame('photo__1_.png', $upload->filename);
    }

    #[Test]
    public function testExtensionMatchingIsCaseInsensitive(): void
    {
        $validator = $this->validator();

        $upload = $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'PHOTO.PNG'));

        $this->assertSame('PHOTO.PNG', $upload->filename);
        $this->assertSame('png', $upload->extension);
    }

    #[Test]
    public function testCompoundExtensionIsMatchedAsAWhole(): void
    {
        $validator = $this->validator(new UploadConstraints(['tar.gz' => ['application/gzip']]));

        $upload = $validator->validateNativeUpload($this->entry(UploadFixtures::GZIP, 'archive.tar.gz'));

        $this->assertSame('archive.tar.gz', $upload->filename);
        $this->assertSame('tar.gz', $upload->extension);
        $this->assertSame('application/gzip', $upload->mimeType);
    }

    #[Test]
    public function testSingleExtensionStillWorksAlongsideCompoundOnes(): void
    {
        $validator = $this->validator(new UploadConstraints(['gz' => ['application/gzip']]));

        $upload = $validator->validateNativeUpload($this->entry(UploadFixtures::GZIP, 'archive.gz'));

        $this->assertSame('gz', $upload->extension);
    }

    #[Test]
    public function testFileAtTheSizeLimitIsAccepted(): void
    {
        $validator = $this->validator(UploadConstraints::images()->withMaxSizeBytes(strlen(UploadFixtures::PNG)));

        $upload = $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png'));

        $this->assertSame(strlen(UploadFixtures::PNG), $upload->sizeBytes);
    }

    // --- Attack cases ---

    #[Test]
    public function testPhpScriptRenamedToAnImageIsRejected(): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Detected MIME type "text/x-php" is not allowed for extension "jpg"');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PHP, 'shell.jpg'));
    }

    #[Test]
    public function testClientProvidedTypeIsIgnored(): void
    {
        $validator = $this->validator();

        $entry         = $this->entry(UploadFixtures::PHP, 'shell.png');
        $entry['type'] = 'image/png';

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Detected MIME type "text/x-php"');

        $validator->validateNativeUpload($entry);
    }

    #[Test]
    public function testDoubleExtensionIsRejected(): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Filename "shell.php.png" carries more than one extension');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'shell.php.png'));
    }

    #[Test]
    public function testCompoundExtensionIsRejectedWhenOnlyTheSuffixIsAllowed(): void
    {
        $validator = $this->validator(new UploadConstraints(['gz' => ['application/gzip']]));

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('carries more than one extension');

        $validator->validateNativeUpload($this->entry(UploadFixtures::GZIP, 'archive.tar.gz'));
    }

    #[Test]
    public function testMultipleExtensionsCanBeAllowedExplicitly(): void
    {
        $validator = $this->validator(UploadConstraints::images()->withMultipleExtensions());

        $upload = $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'holiday.2024.png'));

        $this->assertSame('holiday.2024.png', $upload->filename);
        $this->assertSame('png', $upload->extension);
    }

    #[Test]
    public function testEveryDotIsConsideredWhenLookingForTheExtension(): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Filename "a..png" carries more than one extension');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'a..png'));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function rejectedExtensionProvider(): array
    {
        return [
            'not on the allow-list' => ['photo.bmp'],
            'no extension at all'   => ['photo'],
            'php extension'         => ['shell.php'],
            'extension only'        => ['png'],
        ];
    }

    #[DataProvider('rejectedExtensionProvider')]
    #[Test]
    public function testUnknownExtensionIsRejected(string $filename): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('No allowed file extension found');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, $filename));
    }

    #[Test]
    public function testNullByteInTheFilenameIsRejected(): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('NUL byte');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, "photo.png\0.php"));
    }

    #[Test]
    public function testControlCharacterInTheFilenameIsRejected(): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('control characters');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, "photo\r\n.png"));
    }

    #[Test]
    public function testReservedDeviceNameIsRejected(): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('reserved device name');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'NUL.png'));
    }

    #[Test]
    public function testOverlongFilenameIsRejected(): void
    {
        $validator = $this->validator(UploadConstraints::images()->withMaxFilenameLength(8));

        $this->expectException(InvalidFilenameException::class);
        $this->expectExceptionMessage('the maximum is 8');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photograph.png'));
    }

    // --- Size ---

    #[Test]
    public function testEmptyFileIsRejected(): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Uploaded file is empty');

        $validator->validateNativeUpload($this->entry('', 'photo.png'));
    }

    #[Test]
    public function testOversizedFileIsRejected(): void
    {
        $limit     = strlen(UploadFixtures::PNG) - 1;
        $validator = $this->validator(UploadConstraints::images()->withMaxSizeBytes($limit));

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage(sprintf(
            'Uploaded file is %d bytes, the maximum is %d',
            strlen(UploadFixtures::PNG),
            $limit
        ));

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png'));
    }

    #[Test]
    public function testTheRealSizeIsUsedInsteadOfTheReportedOne(): void
    {
        $validator = $this->validator(UploadConstraints::images()->withMaxSizeBytes(strlen(UploadFixtures::PNG)));

        $entry         = $this->entry(UploadFixtures::PNG, 'photo.png');
        $entry['size'] = 1;

        $this->assertSame(strlen(UploadFixtures::PNG), $validator->validateNativeUpload($entry)->sizeBytes);
    }

    // --- Upload error codes ---

    /**
     * @return array<string, array{int, string}>
     */
    public static function failedUploadProvider(): array
    {
        return [
            'ini size'   => [UPLOAD_ERR_INI_SIZE, 'the file exceeds the upload_max_filesize directive'],
            'form size'  => [UPLOAD_ERR_FORM_SIZE, 'the file exceeds the MAX_FILE_SIZE form field'],
            'partial'    => [UPLOAD_ERR_PARTIAL, 'the file was only partially uploaded'],
            'no file'    => [UPLOAD_ERR_NO_FILE, 'no file was uploaded'],
            'no tmp dir' => [UPLOAD_ERR_NO_TMP_DIR, 'the temporary upload directory is missing'],
            'cant write' => [UPLOAD_ERR_CANT_WRITE, 'the file could not be written to disk'],
            'extension'  => [UPLOAD_ERR_EXTENSION, 'a PHP extension stopped the upload'],
        ];
    }

    #[DataProvider('failedUploadProvider')]
    #[Test]
    public function testFailedUploadIsRejected(int $error, string $reason): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage(sprintf('Upload failed (code %d): %s', $error, $reason));

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png', $error));
    }

    /**
     * @return array<string, array{int}>
     */
    public static function unknownErrorCodeProvider(): array
    {
        return [
            'never assigned'  => [5],
            'above the range' => [9],
            'negative'        => [-1],
        ];
    }

    #[DataProvider('unknownErrorCodeProvider')]
    #[Test]
    public function testUnknownErrorCodeIsRejected(int $error): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage(sprintf('unknown error code %d', $error));

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png', $error));
    }

    // --- Malformed entries ---

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function malformedEntryProvider(): array
    {
        return [
            'empty entry'      => [[], 'error'],
            'error as string'  => [['error' => '0'], 'error'],
            'missing name'     => [['error' => 0], 'name'],
            'name as int'      => [['error' => 0, 'name' => 1], 'name'],
            'missing tmp_name' => [['error' => 0, 'name' => 'photo.png'], 'tmp_name'],
            'tmp_name as null' => [['error' => 0, 'name' => 'photo.png', 'tmp_name' => null], 'tmp_name'],
        ];
    }

    /**
     * @param array<string, mixed> $entry
     */
    #[DataProvider('malformedEntryProvider')]
    #[Test]
    public function testMalformedEntryIsRejected(array $entry, string $field): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage(sprintf('"%s" is missing or has the wrong type', $field));

        $validator->validateNativeUpload($entry);
    }

    // --- is_uploaded_file ---

    #[Test]
    public function testFileNotCreatedByAnUploadIsRejected(): void
    {
        $validator = $this->validator(uploaded: false);

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('not created by an HTTP upload');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png'));
    }

    #[Test]
    public function testTheDefaultCheckerRejectsOrdinaryFiles(): void
    {
        // Constructed without any collaborator, so the real
        // NativeUploadedFileChecker and FinfoMimeTypeDetector are used
        $validator = new UploadValidator(UploadConstraints::images());

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('not created by an HTTP upload');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png'));
    }

    #[Test]
    public function testMissingTemporaryFileIsRejected(): void
    {
        $validator = $this->validator();

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Uploaded file is empty');

        $validator->validateNativeUpload([
            'name'     => 'photo.png',
            'tmp_name' => '/nonexistent/upload.tmp',
            'error'    => UPLOAD_ERR_OK,
            'size'     => 100,
        ]);
    }

    // --- MIME detection ---

    #[Test]
    public function testDetectionFailureIsRejected(): void
    {
        $validator = $this->validator(detector: new FakeMimeTypeDetector(null));

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Could not detect the MIME type');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png'));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function malformedDetectedTypeProvider(): array
    {
        return [
            'not a type'    => ['definitely not a mime type'],
            'header inject' => ["image/png\r\nX-Injected: 1"],
            'empty'         => [''],
            'only a slash'  => ['/'],
        ];
    }

    #[DataProvider('malformedDetectedTypeProvider')]
    #[Test]
    public function testMalformedDetectedTypeIsRejected(string $detected): void
    {
        $validator = $this->validator(detector: new FakeMimeTypeDetector($detected));

        $this->expectException(InvalidUploadException::class);
        $this->expectExceptionMessage('Could not detect the MIME type');

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png'));
    }

    #[Test]
    public function testDetectedTypeIsTrimmed(): void
    {
        $validator = $this->validator(detector: new FakeMimeTypeDetector('  image/png  '));

        $upload = $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png'));

        $this->assertSame('image/png', $upload->mimeType);
    }

    #[Test]
    public function testDetectedTypeIsLowercasedAndStrippedOfParameters(): void
    {
        $validator = $this->validator(detector: new FakeMimeTypeDetector('IMAGE/PNG; charset=binary'));

        $upload = $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png'));

        $this->assertSame('image/png', $upload->mimeType);
    }

    // --- Logging ---

    #[Test]
    public function testRejectionIsLogged(): void
    {
        $logger    = new RecordingLogger();
        $validator = $this->validator(logger: $logger);

        try {
            $validator->validateNativeUpload($this->entry(UploadFixtures::PHP, 'shell.jpg'));
            $this->fail('Expected the upload to be rejected');
        } catch (InvalidUploadException) {
            // expected
        }

        $this->assertCount(1, $logger->warnings);
        $this->assertSame('File upload rejected', $logger->warnings[0]['message']);
        $this->assertArrayHasKey('reason', $logger->warnings[0]['context']);
        $this->assertSame(
            'Detected MIME type "text/x-php" is not allowed for extension "jpg"',
            $logger->warnings[0]['context']['reason']
        );
    }

    #[Test]
    public function testFilenameRejectionIsLoggedAsWell(): void
    {
        $logger    = new RecordingLogger();
        $validator = $this->validator(logger: $logger);

        try {
            $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, "photo\0.png"));
            $this->fail('Expected the upload to be rejected');
        } catch (InvalidFilenameException) {
            // expected
        }

        $this->assertCount(1, $logger->warnings);
        $this->assertSame('Filename contains a NUL byte', $logger->warnings[0]['context']['reason']);
    }

    #[Test]
    public function testAcceptedUploadIsNotLogged(): void
    {
        $logger    = new RecordingLogger();
        $validator = $this->validator(logger: $logger);

        $validator->validateNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png'));

        $this->assertSame([], $logger->warnings);
    }

    // --- Non-throwing API ---

    #[Test]
    public function testIsValidNativeUploadReturnsTrue(): void
    {
        $validator = $this->validator();

        $this->assertTrue($validator->isValidNativeUpload($this->entry(UploadFixtures::PNG, 'photo.png')));
    }

    #[Test]
    public function testIsValidNativeUploadReturnsFalseOnMimeMismatch(): void
    {
        $validator = $this->validator();

        $this->assertFalse($validator->isValidNativeUpload($this->entry(UploadFixtures::PHP, 'shell.jpg')));
    }

    #[Test]
    public function testIsValidNativeUploadReturnsFalseOnBadFilename(): void
    {
        $validator = $this->validator();

        $this->assertFalse($validator->isValidNativeUpload($this->entry(UploadFixtures::PNG, "photo\0.png")));
    }

    // --- Helpers ---

    private function validator(
        ?UploadConstraints $constraints = null,
        ?RecordingLogger $logger = null,
        ?FakeMimeTypeDetector $detector = null,
        bool $uploaded = true,
    ): UploadValidator {
        return new UploadValidator(
            $constraints ?? UploadConstraints::images(),
            $logger,
            $detector ?? new FinfoMimeTypeDetector(),
            new FakeUploadedFileChecker($uploaded)
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function entry(string $content, string $name, int $error = UPLOAD_ERR_OK): array
    {
        $path = tempnam(sys_get_temp_dir(), 'zzp-upload-');
        $this->assertIsString($path);

        $this->temporaryFiles[] = $path;

        file_put_contents($path, $content);

        return [
            'name'     => $name,
            'type'     => 'application/octet-stream',
            'tmp_name' => $path,
            'error'    => $error,
            'size'     => strlen($content),
        ];
    }
}
