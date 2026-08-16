<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Upload;

/**
 * PHP upload error codes (the UPLOAD_ERR_* constants)
 *
 * Backed by the literal values rather than the constants so the enum
 * stays a pure compile-time definition. Value 5 is deliberately absent -
 * it has never been assigned by PHP.
 *
 * @see https://www.php.net/manual/en/features.file-upload.errors.php
 */
enum UploadErrorCode: int
{
    /** UPLOAD_ERR_OK */
    case Ok = 0;

    /** UPLOAD_ERR_INI_SIZE */
    case IniSize = 1;

    /** UPLOAD_ERR_FORM_SIZE */
    case FormSize = 2;

    /** UPLOAD_ERR_PARTIAL */
    case Partial = 3;

    /** UPLOAD_ERR_NO_FILE */
    case NoFile = 4;

    /** UPLOAD_ERR_NO_TMP_DIR */
    case NoTmpDir = 6;

    /** UPLOAD_ERR_CANT_WRITE */
    case CantWrite = 7;

    /** UPLOAD_ERR_EXTENSION */
    case StoppedByExtension = 8;

    /**
     * Whether the upload completed successfully
     */
    public function isSuccess(): bool
    {
        return $this === self::Ok;
    }

    /**
     * Human readable description of the code
     */
    public function reason(): string
    {
        return match ($this) {
            self::Ok                 => 'the file was uploaded successfully',
            self::IniSize            => 'the file exceeds the upload_max_filesize directive',
            self::FormSize           => 'the file exceeds the MAX_FILE_SIZE form field',
            self::Partial            => 'the file was only partially uploaded',
            self::NoFile             => 'no file was uploaded',
            self::NoTmpDir           => 'the temporary upload directory is missing',
            self::CantWrite          => 'the file could not be written to disk',
            self::StoppedByExtension => 'a PHP extension stopped the upload',
        };
    }
}
