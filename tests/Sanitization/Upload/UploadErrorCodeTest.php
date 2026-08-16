<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Upload\UploadErrorCode;

#[CoversClass(UploadErrorCode::class)]
final class UploadErrorCodeTest extends TestCase
{
    /**
     * @return array<string, array{UploadErrorCode, int}>
     */
    public static function nativeConstantProvider(): array
    {
        return [
            'ok'         => [UploadErrorCode::Ok, UPLOAD_ERR_OK],
            'ini size'   => [UploadErrorCode::IniSize, UPLOAD_ERR_INI_SIZE],
            'form size'  => [UploadErrorCode::FormSize, UPLOAD_ERR_FORM_SIZE],
            'partial'    => [UploadErrorCode::Partial, UPLOAD_ERR_PARTIAL],
            'no file'    => [UploadErrorCode::NoFile, UPLOAD_ERR_NO_FILE],
            'no tmp dir' => [UploadErrorCode::NoTmpDir, UPLOAD_ERR_NO_TMP_DIR],
            'cant write' => [UploadErrorCode::CantWrite, UPLOAD_ERR_CANT_WRITE],
            'extension'  => [UploadErrorCode::StoppedByExtension, UPLOAD_ERR_EXTENSION],
        ];
    }

    #[DataProvider('nativeConstantProvider')]
    #[Test]
    public function testCaseMatchesTheNativeConstant(UploadErrorCode $code, int $expected): void
    {
        $this->assertSame($expected, $code->value);
    }

    #[Test]
    public function testOnlyOkIsSuccess(): void
    {
        $this->assertTrue(UploadErrorCode::Ok->isSuccess());

        foreach (UploadErrorCode::cases() as $code) {
            if ($code === UploadErrorCode::Ok) {
                continue;
            }

            $this->assertFalse($code->isSuccess(), $code->name . ' must not be a success');
        }
    }

    /**
     * @return array<string, array{UploadErrorCode, string}>
     */
    public static function reasonProvider(): array
    {
        return [
            'ok'         => [UploadErrorCode::Ok, 'the file was uploaded successfully'],
            'ini size'   => [UploadErrorCode::IniSize, 'the file exceeds the upload_max_filesize directive'],
            'form size'  => [UploadErrorCode::FormSize, 'the file exceeds the MAX_FILE_SIZE form field'],
            'partial'    => [UploadErrorCode::Partial, 'the file was only partially uploaded'],
            'no file'    => [UploadErrorCode::NoFile, 'no file was uploaded'],
            'no tmp dir' => [UploadErrorCode::NoTmpDir, 'the temporary upload directory is missing'],
            'cant write' => [UploadErrorCode::CantWrite, 'the file could not be written to disk'],
            'extension'  => [UploadErrorCode::StoppedByExtension, 'a PHP extension stopped the upload'],
        ];
    }

    #[DataProvider('reasonProvider')]
    #[Test]
    public function testReason(UploadErrorCode $code, string $expected): void
    {
        $this->assertSame($expected, $code->reason());
    }

    #[Test]
    public function testValueFiveIsNotAssigned(): void
    {
        $unusedErrorCode = 5;

        $this->assertNull(UploadErrorCode::tryFrom($unusedErrorCode));
    }

    #[Test]
    public function testUnknownValuesAreNotAccepted(): void
    {
        $outOfRangeCode = 9;

        $this->assertNull(UploadErrorCode::tryFrom(-1));
        $this->assertNull(UploadErrorCode::tryFrom($outOfRangeCode));
    }

    #[Test]
    public function testAllCasesAreCovered(): void
    {
        $this->assertCount(8, UploadErrorCode::cases());
    }
}
