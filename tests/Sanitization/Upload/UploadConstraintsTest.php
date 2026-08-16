<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw InvalidUploadConstraintsException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Exception\InvalidUploadConstraintsException;
use Zappzarapp\Security\Sanitization\Upload\FilenameSanitizer;
use Zappzarapp\Security\Sanitization\Upload\UploadConstraints;

#[CoversClass(UploadConstraints::class)]
final class UploadConstraintsTest extends TestCase
{
    // --- Defaults ---

    #[Test]
    public function testDefaults(): void
    {
        $constraints = new UploadConstraints(['pdf' => ['application/pdf']]);

        $this->assertSame(['pdf' => ['application/pdf']], $constraints->allowedTypes);
        $this->assertSame(UploadConstraints::DEFAULT_MAX_SIZE_BYTES, $constraints->maxSizeBytes);
        $this->assertSame(5_242_880, $constraints->maxSizeBytes);
        $this->assertFalse($constraints->multipleExtensions);
        $this->assertSame(FilenameSanitizer::DEFAULT_MAX_LENGTH, $constraints->maxFilenameLength);
        $this->assertFalse($constraints->unicodeFilenames);
    }

    // --- Allow-list normalization ---

    #[Test]
    public function testExtensionsAreLowercasedAndStrippedOfLeadingDots(): void
    {
        $constraints = new UploadConstraints(['.JPG' => ['IMAGE/JPEG']]);

        $this->assertSame(['jpg' => ['image/jpeg']], $constraints->allowedTypes);
    }

    #[Test]
    public function testMimeTypesAreTrimmed(): void
    {
        $constraints = new UploadConstraints(['pdf' => ['  application/PDF  ']]);

        $this->assertSame(['pdf' => ['application/pdf']], $constraints->allowedTypes);
    }

    #[Test]
    public function testCompoundExtensionsAreAccepted(): void
    {
        $constraints = new UploadConstraints(['tar.gz' => ['application/gzip']]);

        $this->assertSame(['tar.gz' => ['application/gzip']], $constraints->allowedTypes);
    }

    #[Test]
    public function testNumericExtensionKeysAreHandled(): void
    {
        // PHP silently turns a numeric string key into an int, which
        // would break every string operation on it
        $constraints = new UploadConstraints(['123' => ['application/pdf']]);

        $this->assertSame(['123' => ['application/pdf']], $constraints->allowedTypes);
    }

    #[Test]
    public function testSeveralMimeTypesPerExtension(): void
    {
        $constraints = new UploadConstraints(['csv' => ['text/csv', 'text/plain']]);

        $this->assertSame(['csv' => ['text/csv', 'text/plain']], $constraints->allowedTypes);
    }

    // --- Rejected configuration ---

    #[Test]
    public function testEmptyAllowListIsRejected(): void
    {
        $this->expectException(InvalidUploadConstraintsException::class);
        $this->expectExceptionMessage('non-empty extension allow-list');

        new UploadConstraints([]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidExtensionProvider(): array
    {
        return [
            'empty'         => [''],
            'only a dot'    => ['.'],
            'with a slash'  => ['a/b'],
            'with a space'  => ['jp g'],
            'with a dash'   => ['tar-gz'],
            'trailing dot'  => ['jpg.'],
            'with a colon'  => ['jp:g'],
        ];
    }

    #[DataProvider('invalidExtensionProvider')]
    #[Test]
    public function testInvalidExtensionIsRejected(string $extension): void
    {
        $this->expectException(InvalidUploadConstraintsException::class);
        $this->expectExceptionMessage('Invalid allow-list extension');

        new UploadConstraints([$extension => ['application/pdf']]);
    }

    #[Test]
    public function testExtensionWithoutMimeTypesIsRejected(): void
    {
        $this->expectException(InvalidUploadConstraintsException::class);
        $this->expectExceptionMessage('Extension "pdf" must be mapped to at least one MIME type');

        new UploadConstraints(['pdf' => []]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidMimeTypeProvider(): array
    {
        return [
            'empty'            => [''],
            'no subtype'       => ['application'],
            'no type'          => ['/pdf'],
            'with a semicolon' => ['text/plain; charset=utf-8'],
            'with a newline'   => ["text/plain\nX-Injected: 1"],
            'with a space'     => ['text /plain'],
            'two slashes'      => ['a/b/c'],
        ];
    }

    #[DataProvider('invalidMimeTypeProvider')]
    #[Test]
    public function testInvalidMimeTypeIsRejected(string $mimeType): void
    {
        $this->expectException(InvalidUploadConstraintsException::class);
        $this->expectExceptionMessage('Invalid MIME type');

        new UploadConstraints(['pdf' => [$mimeType]]);
    }

    #[Test]
    public function testNonPositiveMaxSizeIsRejected(): void
    {
        $this->expectException(InvalidUploadConstraintsException::class);
        $this->expectExceptionMessage('Maximum upload size must be at least 1 byte, got 0');

        new UploadConstraints(['pdf' => ['application/pdf']], 0);
    }

    #[Test]
    public function testMaxSizeOfOneByteIsAccepted(): void
    {
        $constraints = new UploadConstraints(['pdf' => ['application/pdf']], 1);

        $this->assertSame(1, $constraints->maxSizeBytes);
    }

    #[Test]
    public function testNonPositiveMaxFilenameLengthIsRejected(): void
    {
        $this->expectException(InvalidUploadConstraintsException::class);
        $this->expectExceptionMessage('Maximum filename length must be at least 1 byte, got 0');

        new UploadConstraints(['pdf' => ['application/pdf']], maxFilenameLength: 0);
    }

    #[Test]
    public function testMaxFilenameLengthOfOneIsAccepted(): void
    {
        $constraints = new UploadConstraints(['pdf' => ['application/pdf']], maxFilenameLength: 1);

        $this->assertSame(1, $constraints->maxFilenameLength);
    }

    // --- Immutable modifiers ---

    #[Test]
    public function testWithAllowedTypesReturnsANewInstance(): void
    {
        $constraints = new UploadConstraints(['pdf' => ['application/pdf']], 42, true, 64, true);
        $changed     = $constraints->withAllowedTypes(['png' => ['image/png']]);

        $this->assertNotSame($constraints, $changed);
        $this->assertSame(['pdf' => ['application/pdf']], $constraints->allowedTypes);
        $this->assertSame(['png' => ['image/png']], $changed->allowedTypes);
        $this->assertSame(42, $changed->maxSizeBytes);
        $this->assertTrue($changed->multipleExtensions);
        $this->assertSame(64, $changed->maxFilenameLength);
        $this->assertTrue($changed->unicodeFilenames);
    }

    #[Test]
    public function testWithMaxSizeBytesReturnsANewInstance(): void
    {
        $constraints = new UploadConstraints(['pdf' => ['application/pdf']], 42, true, 64, true);
        $changed     = $constraints->withMaxSizeBytes(99);

        $this->assertNotSame($constraints, $changed);
        $this->assertSame(42, $constraints->maxSizeBytes);
        $this->assertSame(99, $changed->maxSizeBytes);
        $this->assertSame(['pdf' => ['application/pdf']], $changed->allowedTypes);
        $this->assertTrue($changed->multipleExtensions);
        $this->assertSame(64, $changed->maxFilenameLength);
        $this->assertTrue($changed->unicodeFilenames);
    }

    #[Test]
    public function testWithMultipleExtensionsReturnsANewInstance(): void
    {
        $constraints = new UploadConstraints(['pdf' => ['application/pdf']], 42, false, 64, true);
        $changed     = $constraints->withMultipleExtensions();

        $this->assertNotSame($constraints, $changed);
        $this->assertFalse($constraints->multipleExtensions);
        $this->assertTrue($changed->multipleExtensions);
        $this->assertSame(['pdf' => ['application/pdf']], $changed->allowedTypes);
        $this->assertSame(42, $changed->maxSizeBytes);
        $this->assertSame(64, $changed->maxFilenameLength);
        $this->assertTrue($changed->unicodeFilenames);
    }

    #[Test]
    public function testWithMaxFilenameLengthReturnsANewInstance(): void
    {
        $constraints = new UploadConstraints(['pdf' => ['application/pdf']], 42, true, 64, true);
        $changed     = $constraints->withMaxFilenameLength(12);

        $this->assertNotSame($constraints, $changed);
        $this->assertSame(64, $constraints->maxFilenameLength);
        $this->assertSame(12, $changed->maxFilenameLength);
        $this->assertSame(['pdf' => ['application/pdf']], $changed->allowedTypes);
        $this->assertSame(42, $changed->maxSizeBytes);
        $this->assertTrue($changed->multipleExtensions);
        $this->assertTrue($changed->unicodeFilenames);
    }

    #[Test]
    public function testWithUnicodeFilenamesReturnsANewInstance(): void
    {
        $constraints = new UploadConstraints(['pdf' => ['application/pdf']], 42, true, 64, false);
        $changed     = $constraints->withUnicodeFilenames();

        $this->assertNotSame($constraints, $changed);
        $this->assertFalse($constraints->unicodeFilenames);
        $this->assertTrue($changed->unicodeFilenames);
        $this->assertSame(['pdf' => ['application/pdf']], $changed->allowedTypes);
        $this->assertSame(42, $changed->maxSizeBytes);
        $this->assertTrue($changed->multipleExtensions);
        $this->assertSame(64, $changed->maxFilenameLength);
    }

    // --- Presets ---

    #[Test]
    public function testImagesPreset(): void
    {
        $constraints = UploadConstraints::images();

        $this->assertSame([
            'jpg'  => ['image/jpeg'],
            'jpeg' => ['image/jpeg'],
            'png'  => ['image/png'],
            'gif'  => ['image/gif'],
            'webp' => ['image/webp'],
        ], $constraints->allowedTypes);
        $this->assertSame(UploadConstraints::DEFAULT_MAX_SIZE_BYTES, $constraints->maxSizeBytes);
        $this->assertFalse($constraints->multipleExtensions);
    }

    #[Test]
    public function testImagesPresetExcludesSvg(): void
    {
        $this->assertArrayNotHasKey('svg', UploadConstraints::images()->allowedTypes);
    }

    #[Test]
    public function testDocumentsPreset(): void
    {
        $constraints = UploadConstraints::documents();

        $this->assertSame([
            'pdf' => ['application/pdf'],
            'txt' => ['text/plain'],
            'csv' => ['text/csv', 'text/plain'],
        ], $constraints->allowedTypes);
        $this->assertSame(UploadConstraints::DEFAULT_MAX_SIZE_BYTES, $constraints->maxSizeBytes);
        $this->assertFalse($constraints->multipleExtensions);
    }

    #[Test]
    public function testDocumentsPresetExcludesZipContainers(): void
    {
        $allowed = UploadConstraints::documents()->allowedTypes;

        $this->assertArrayNotHasKey('docx', $allowed);
        $this->assertArrayNotHasKey('xlsx', $allowed);
    }
}
