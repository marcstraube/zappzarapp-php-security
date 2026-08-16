<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Exception;

use RuntimeException;

/**
 * Exception thrown when a file upload fails validation
 *
 * Every interpolated value has already passed validation (sanitized
 * filename, allow-list extension, syntactically checked MIME type), so
 * messages are safe to log and cannot carry a header injection payload.
 */
final class InvalidUploadException extends RuntimeException
{
    /**
     * Create for a PHP upload error code
     *
     * @param int $code The UPLOAD_ERR_* code
     * @param string $reason Human readable description of the code
     */
    public static function uploadFailed(int $code, string $reason): self
    {
        return new self(sprintf('Upload failed (code %d): %s', $code, $reason));
    }

    /**
     * Create for an unknown UPLOAD_ERR_* code
     */
    public static function unknownErrorCode(int $code): self
    {
        return new self(sprintf('Upload failed with unknown error code %d', $code));
    }

    /**
     * Create for a malformed $_FILES entry
     *
     * @param string $field The missing or mistyped key
     */
    public static function malformedEntry(string $field): self
    {
        return new self(sprintf('Malformed upload entry: "%s" is missing or has the wrong type', $field));
    }

    /**
     * Create for a temporary file that was not produced by an HTTP upload
     */
    public static function notAnUploadedFile(): self
    {
        return new self('Temporary file was not created by an HTTP upload');
    }

    /**
     * Create for an empty upload
     */
    public static function emptyFile(): self
    {
        return new self('Uploaded file is empty');
    }

    /**
     * Create for an upload exceeding the size limit
     */
    public static function tooLarge(int $sizeBytes, int $maxSizeBytes): self
    {
        return new self(sprintf(
            'Uploaded file is %d bytes, the maximum is %d',
            $sizeBytes,
            $maxSizeBytes
        ));
    }

    /**
     * Create for a PSR-7 upload without a client filename
     */
    public static function missingClientFilename(): self
    {
        return new self('Uploaded file has no client filename');
    }

    /**
     * Create for a filename whose extension is not on the allow-list
     *
     * @param string $filename The sanitized filename
     */
    public static function extensionNotAllowed(string $filename): self
    {
        return new self(sprintf('No allowed file extension found in "%s"', $filename));
    }

    /**
     * Create for a filename carrying more than one extension
     *
     * @param string $filename The sanitized filename
     */
    public static function multipleExtensions(string $filename): self
    {
        return new self(sprintf('Filename "%s" carries more than one extension', $filename));
    }

    /**
     * Create when the real MIME type could not be detected
     */
    public static function mimeDetectionFailed(): self
    {
        return new self('Could not detect the MIME type of the uploaded file');
    }

    /**
     * Create when the detected MIME type is not allowed for the extension
     *
     * @param string $extension The allow-list extension
     * @param string $detectedMimeType The syntactically validated detected type
     */
    public static function mimeTypeMismatch(string $extension, string $detectedMimeType): self
    {
        return new self(sprintf(
            'Detected MIME type "%s" is not allowed for extension "%s"',
            $detectedMimeType,
            $extension
        ));
    }
}
