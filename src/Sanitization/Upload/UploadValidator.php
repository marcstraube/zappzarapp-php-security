<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Upload;

use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UploadedFileInterface;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;
use Zappzarapp\Security\Sanitization\Exception\InvalidFilenameException;
use Zappzarapp\Security\Sanitization\Exception\InvalidUploadException;

/**
 * Allow-list based validation of file uploads
 *
 * Accepts both native `$_FILES` entries and PSR-7 `UploadedFileInterface`
 * instances and applies the same checks to either:
 *
 * 1. the `UPLOAD_ERR_*` code reports success;
 * 2. for native uploads, `is_uploaded_file()` confirms PHP created the
 *    temporary file - a forged `tmp_name` cannot point the validator at
 *    an arbitrary file on disk;
 * 3. the real byte count is within the size limit (the client reported
 *    size is ignored entirely);
 * 4. the filename survives {@see FilenameSanitizer};
 * 5. a suffix of the filename is on the extension allow-list, and the
 *    remaining stem carries no further extension;
 * 6. the MIME type detected from the *content* is one of the types
 *    mapped to that extension.
 *
 * Nothing the client asserts is trusted: neither the `type` field of the
 * multipart part, nor the reported size, nor the filename.
 *
 * ## What this does not do
 *
 * Validation is a check on bytes at a point in time, not a guarantee
 * about the file later on:
 *
 * - **TOCTOU.** Between validation and `move_uploaded_file()` the
 *   temporary file can still change if the temporary directory is
 *   writable by other users. Move the file first, then validate the
 *   moved copy, or keep the upload directory private to the process.
 * - **Polyglots.** A file can be a valid GIF *and* valid PHP. Content
 *   sniffing reports the leading format. Never store uploads inside the
 *   web root and never let the web server execute them.
 * - **Container formats.** docx, xlsx, odt and jar are ZIP archives and
 *   sniff as `application/zip`; allowing them means allowing any ZIP.
 * - **Malware.** No signature scanning is performed.
 *
 * ## Usage
 *
 * ```php
 * $validator = new UploadValidator(UploadConstraints::images());
 *
 * $upload = $validator->validateNativeUpload($_FILES['avatar']);
 * // $upload->filename, ->extension, ->mimeType, ->sizeBytes
 *
 * // PSR-7
 * $upload = $validator->validateUploadedFile($request->getUploadedFiles()['avatar']);
 * ```
 */
final readonly class UploadValidator
{
    /**
     * Bytes read per stream iteration when buffering a PSR-7 upload
     */
    private const int READ_CHUNK_BYTES = 8192;

    /**
     * A MIME type without parameters (RFC 6838 restricted name syntax)
     *
     * Applied to whatever the detector returns, so a rogue or exotic
     * detector cannot push ";", CR or LF into a header or a log line.
     */
    private const string MIME_TYPE = '#^[a-z0-9][a-z0-9!\#$&^_+.-]*/[a-z0-9][a-z0-9!\#$&^_+.-]*$#';

    private FilenameSanitizer $filenameSanitizer;

    /**
     * @param UploadConstraints $constraints The allow-list and limits
     * @param SecurityLoggerInterface|null $logger Optional logger for rejected uploads
     * @param MimeTypeDetectorInterface $mimeTypeDetector Content sniffing backend
     * @param UploadedFileCheckerInterface $uploadedFileChecker Backend for is_uploaded_file()
     */
    public function __construct(
        private UploadConstraints $constraints,
        private ?SecurityLoggerInterface $logger = null,
        private MimeTypeDetectorInterface $mimeTypeDetector = new FinfoMimeTypeDetector(),
        private UploadedFileCheckerInterface $uploadedFileChecker = new NativeUploadedFileChecker(),
    ) {
        $this->filenameSanitizer = new FilenameSanitizer(
            $constraints->maxFilenameLength,
            $constraints->unicodeFilenames
        );
    }

    /**
     * Validate a single native `$_FILES` entry
     *
     * A multi-file field (`<input type="file" name="docs[]">`) produces
     * one entry whose `name`, `tmp_name` and `error` are arrays. Split it
     * into per-file entries first; passing it as-is is rejected as a
     * malformed entry rather than silently validating the first file.
     *
     * @param array<string, mixed> $file One entry of the $_FILES superglobal
     *
     * @throws InvalidUploadException If the upload is rejected
     * @throws InvalidFilenameException If no safe filename can be derived
     */
    public function validateNativeUpload(array $file): ValidatedUpload
    {
        try {
            return $this->inspectNativeUpload($file);
        } catch (InvalidFilenameException | InvalidUploadException $exception) {
            $this->logRejection($exception);

            throw $exception;
        }
    }

    /**
     * Validate a PSR-7 uploaded file
     *
     * The stream is buffered in memory for content sniffing, bounded by
     * the configured maximum size plus one read chunk.
     *
     * @throws InvalidUploadException If the upload is rejected
     * @throws InvalidFilenameException If no safe filename can be derived
     */
    public function validateUploadedFile(UploadedFileInterface $file): ValidatedUpload
    {
        try {
            return $this->inspectUploadedFile($file);
        } catch (InvalidFilenameException | InvalidUploadException $exception) {
            $this->logRejection($exception);

            throw $exception;
        }
    }

    /**
     * Whether a native `$_FILES` entry passes validation
     *
     * @param array<string, mixed> $file One entry of the $_FILES superglobal
     */
    public function isValidNativeUpload(array $file): bool
    {
        try {
            $this->validateNativeUpload($file);

            return true;
        } catch (InvalidFilenameException | InvalidUploadException) {
            return false;
        }
    }

    /**
     * Whether a PSR-7 uploaded file passes validation
     */
    public function isValidUploadedFile(UploadedFileInterface $file): bool
    {
        try {
            $this->validateUploadedFile($file);

            return true;
        } catch (InvalidFilenameException | InvalidUploadException) {
            return false;
        }
    }

    /**
     * Run the checks for a native upload
     *
     * @param array<string, mixed> $file
     *
     * @throws InvalidUploadException If the upload is rejected
     * @throws InvalidFilenameException If no safe filename can be derived
     */
    private function inspectNativeUpload(array $file): ValidatedUpload
    {
        $error   = $file['error'] ?? null;
        $name    = $file['name'] ?? null;
        $tmpName = $file['tmp_name'] ?? null;

        if (!is_int($error)) {
            throw InvalidUploadException::malformedEntry('error');
        }

        if (!is_string($name)) {
            throw InvalidUploadException::malformedEntry('name');
        }

        if (!is_string($tmpName)) {
            throw InvalidUploadException::malformedEntry('tmp_name');
        }

        $this->assertUploadSucceeded($error);

        if (!$this->uploadedFileChecker->isUploadedFile($tmpName)) {
            throw InvalidUploadException::notAnUploadedFile();
        }

        $size = $this->fileSize($tmpName);
        $this->assertSizeAccepted($size);

        $filename  = $this->filenameSanitizer->sanitize($name);
        $extension = $this->resolveExtension($filename);
        $mimeType  = $this->normalizeDetectedType($this->mimeTypeDetector->detectFromFile($tmpName));

        $this->assertTypeMatchesExtension($extension, $mimeType);

        return new ValidatedUpload($filename, $extension, $mimeType, $size);
    }

    /**
     * Run the checks for a PSR-7 upload
     *
     * @throws InvalidUploadException If the upload is rejected
     * @throws InvalidFilenameException If no safe filename can be derived
     */
    private function inspectUploadedFile(UploadedFileInterface $file): ValidatedUpload
    {
        $this->assertUploadSucceeded($file->getError());

        $name = $file->getClientFilename();

        if ($name === null) {
            throw InvalidUploadException::missingClientFilename();
        }

        $content = $this->readBounded($file->getStream(), $this->constraints->maxSizeBytes);
        $size    = strlen($content);

        $this->assertSizeAccepted($size);

        $filename  = $this->filenameSanitizer->sanitize($name);
        $extension = $this->resolveExtension($filename);
        $mimeType  = $this->normalizeDetectedType($this->mimeTypeDetector->detectFromBuffer($content));

        $this->assertTypeMatchesExtension($extension, $mimeType);

        return new ValidatedUpload($filename, $extension, $mimeType, $size);
    }

    /**
     * Reject anything but UPLOAD_ERR_OK
     *
     * @throws InvalidUploadException If the code is not a successful upload
     */
    private function assertUploadSucceeded(int $error): void
    {
        $code = UploadErrorCode::tryFrom($error);

        if ($code === null) {
            throw InvalidUploadException::unknownErrorCode($error);
        }

        if (!$code->isSuccess()) {
            throw InvalidUploadException::uploadFailed($code->value, $code->reason());
        }
    }

    /**
     * The real size of the temporary file, 0 when it cannot be stat'ed
     *
     * The size the client reported in the multipart body is never used:
     * only the bytes that actually landed on disk count.
     */
    private function fileSize(string $path): int
    {
        // Suppressed: an unreadable or missing path is a rejected upload,
        // not a PHP warning the application has to deal with
        $size = @filesize($path);

        return $size === false ? 0 : $size;
    }

    /**
     * Reject empty and oversized uploads
     *
     * @throws InvalidUploadException If the size is not acceptable
     */
    private function assertSizeAccepted(int $size): void
    {
        if ($size === 0) {
            throw InvalidUploadException::emptyFile();
        }

        if ($size > $this->constraints->maxSizeBytes) {
            throw InvalidUploadException::tooLarge($size, $this->constraints->maxSizeBytes);
        }
    }

    /**
     * Buffer a stream, reading at most one chunk beyond the limit
     *
     * Reading one chunk too many is what makes an oversized upload
     * detectable without ever holding more than the limit plus a chunk
     * in memory.
     */
    private function readBounded(StreamInterface $stream, int $maxBytes): string
    {
        if ($stream->isSeekable()) {
            $stream->rewind();
        }

        $buffer = '';

        while (strlen($buffer) <= $maxBytes && !$stream->eof()) {
            $chunk = $stream->read(self::READ_CHUNK_BYTES);

            if ($chunk === '') {
                break;
            }

            $buffer .= $chunk;
        }

        return $buffer;
    }

    /**
     * Find the allow-list extension carried by a sanitized filename
     *
     * Suffixes are tried longest first, so a registered compound
     * extension such as `tar.gz` wins over the bare `gz` and keeps
     * `archive.tar.gz` a single-extension name. Whatever remains in
     * front of the match must not contain a further dot unless multiple
     * extensions were explicitly allowed - that is what rejects
     * `shell.php.jpg`.
     *
     * @param string $filename The sanitized filename
     *
     * @return string The matched allow-list extension
     *
     * @throws InvalidUploadException If no allowed extension is carried
     */
    private function resolveExtension(string $filename): string
    {
        $lowered = strtolower($filename);
        $offset  = 0;

        while (($dot = strpos($lowered, '.', $offset)) !== false) {
            $candidate = substr($lowered, $dot + 1);

            if (array_key_exists($candidate, $this->constraints->allowedTypes)) {
                $stem = substr($lowered, 0, $dot);

                if (!$this->constraints->multipleExtensions && str_contains($stem, '.')) {
                    throw InvalidUploadException::multipleExtensions($filename);
                }

                return $candidate;
            }

            $offset = $dot + 1;
        }

        throw InvalidUploadException::extensionNotAllowed($filename);
    }

    /**
     * Reduce a detected type to a bare, syntactically valid MIME type
     *
     * @param string|null $detected What the detector reported
     *
     * @throws InvalidUploadException If nothing usable was detected
     */
    private function normalizeDetectedType(?string $detected): string
    {
        if ($detected === null) {
            throw InvalidUploadException::mimeDetectionFailed();
        }

        $separator = strpos($detected, ';');
        $bare      = $separator === false ? $detected : substr($detected, 0, $separator);
        $bare      = strtolower(trim($bare));

        if (preg_match(self::MIME_TYPE, $bare) !== 1) {
            throw InvalidUploadException::mimeDetectionFailed();
        }

        return $bare;
    }

    /**
     * Reject a detected type that is not mapped to the extension
     *
     * @throws InvalidUploadException If the type does not match
     */
    private function assertTypeMatchesExtension(string $extension, string $mimeType): void
    {
        if (!in_array($mimeType, $this->constraints->allowedTypes[$extension], true)) {
            throw InvalidUploadException::mimeTypeMismatch($extension, $mimeType);
        }
    }

    /**
     * Log a rejected upload
     *
     * Only the exception message is logged: it is built exclusively from
     * validated values and therefore cannot carry a log injection
     * payload from the client filename.
     */
    private function logRejection(InvalidFilenameException | InvalidUploadException $exception): void
    {
        $this->logger?->warning('File upload rejected', [
            'reason' => $exception->getMessage(),
        ]);
    }
}
