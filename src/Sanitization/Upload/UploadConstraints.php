<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Upload;

use Zappzarapp\Security\Sanitization\Exception\InvalidUploadConstraintsException;

/**
 * Allow-list based constraints for file uploads
 *
 * There is deliberately no permissive default: the allow-list is a
 * required constructor argument and must map every accepted extension to
 * the MIME types that content sniffing is allowed to report for it. An
 * upload is accepted only when the extension is on the list *and* the
 * detected type is one of its mapped types, which is what stops a PHP
 * script from being stored as `avatar.jpg`.
 *
 * Extensions may be compound (`tar.gz`). Together with the default
 * rejection of multiple extensions this is what separates the legitimate
 * `archive.tar.gz` - allowed only if `tar.gz` is on the list - from the
 * classic `shell.php.jpg`.
 *
 * ## Usage
 *
 * ```php
 * $constraints = new UploadConstraints(
 *     allowedTypes: ['pdf' => ['application/pdf']],
 *     maxSizeBytes: 2 * 1024 * 1024,
 * );
 *
 * // Or start from a preset and narrow it down
 * $constraints = UploadConstraints::images()->withMaxSizeBytes(512_000);
 * ```
 */
final readonly class UploadConstraints
{
    /**
     * Default maximum upload size (5 MiB)
     */
    public const int DEFAULT_MAX_SIZE_BYTES = 5_242_880;

    /**
     * A single extension segment: lowercase alphanumerics
     */
    private const string EXTENSION_SEGMENT = '/^[a-z0-9]+(?:\.[a-z0-9]+)*$/';

    /**
     * A MIME type without parameters (RFC 6838 restricted name syntax)
     */
    private const string MIME_TYPE = '#^[a-z0-9][a-z0-9!\#$&^_+.-]*/[a-z0-9][a-z0-9!\#$&^_+.-]*$#';

    /**
     * Extension (lowercase, no leading dot) mapped to its allowed MIME types
     *
     * Keyed by array-key rather than string because PHP coerces a
     * numeric extension such as "123" into an int array key.
     *
     * @var non-empty-array<array-key, non-empty-list<string>>
     */
    public array $allowedTypes;

    /**
     * @param array<array-key, list<string>> $allowedTypes Extension => allowed MIME types
     * @param int $maxSizeBytes Maximum accepted size of the stored content
     * @param bool $multipleExtensions Accept names such as "report.2024.pdf"
     * @param int $maxFilenameLength Maximum length of the sanitized filename in bytes
     * @param bool $unicodeFilenames Keep Unicode letters in the sanitized filename
     *
     * @throws InvalidUploadConstraintsException If the configuration is not usable
     */
    public function __construct(
        array $allowedTypes,
        public int $maxSizeBytes = self::DEFAULT_MAX_SIZE_BYTES,
        public bool $multipleExtensions = false,
        public int $maxFilenameLength = FilenameSanitizer::DEFAULT_MAX_LENGTH,
        public bool $unicodeFilenames = false,
    ) {
        if ($maxSizeBytes < 1) {
            throw InvalidUploadConstraintsException::invalidMaxSize($maxSizeBytes);
        }

        if ($maxFilenameLength < 1) {
            throw InvalidUploadConstraintsException::invalidMaxFilenameLength($maxFilenameLength);
        }

        $this->allowedTypes = $this->normalizeAllowedTypes($allowedTypes);
    }

    /**
     * Create with a different allow-list
     *
     * @param array<array-key, list<string>> $allowedTypes Extension => allowed MIME types
     *
     * @throws InvalidUploadConstraintsException If the allow-list is not usable
     */
    public function withAllowedTypes(array $allowedTypes): self
    {
        return new self(
            $allowedTypes,
            $this->maxSizeBytes,
            $this->multipleExtensions,
            $this->maxFilenameLength,
            $this->unicodeFilenames
        );
    }

    /**
     * Create with a different size limit
     *
     * @throws InvalidUploadConstraintsException If the size is not positive
     */
    public function withMaxSizeBytes(int $maxSizeBytes): self
    {
        return new self(
            $this->allowedTypes,
            $maxSizeBytes,
            $this->multipleExtensions,
            $this->maxFilenameLength,
            $this->unicodeFilenames
        );
    }

    /**
     * Create with multiple extensions accepted
     *
     * Opt-in only: it re-enables names such as "invoice.2024.pdf", but
     * also "shell.php.pdf".
     *
     * @throws InvalidUploadConstraintsException Never - the allow-list is already normalized
     */
    public function withMultipleExtensions(): self
    {
        return new self(
            $this->allowedTypes,
            $this->maxSizeBytes,
            true,
            $this->maxFilenameLength,
            $this->unicodeFilenames
        );
    }

    /**
     * Create with a different filename length limit
     *
     * @throws InvalidUploadConstraintsException If the length is not positive
     */
    public function withMaxFilenameLength(int $maxFilenameLength): self
    {
        return new self(
            $this->allowedTypes,
            $this->maxSizeBytes,
            $this->multipleExtensions,
            $maxFilenameLength,
            $this->unicodeFilenames
        );
    }

    /**
     * Create with Unicode filenames accepted
     *
     * @throws InvalidUploadConstraintsException Never - the allow-list is already normalized
     */
    public function withUnicodeFilenames(): self
    {
        return new self(
            $this->allowedTypes,
            $this->maxSizeBytes,
            $this->multipleExtensions,
            $this->maxFilenameLength,
            true
        );
    }

    /**
     * Common web image formats
     *
     * SVG is deliberately absent: it is an XML document that can carry
     * script and is served as an image.
     *
     * @throws InvalidUploadConstraintsException Never - the preset is valid
     */
    public static function images(): self
    {
        return new self([
            'jpg'  => ['image/jpeg'],
            'jpeg' => ['image/jpeg'],
            'png'  => ['image/png'],
            'gif'  => ['image/gif'],
            'webp' => ['image/webp'],
        ]);
    }

    /**
     * Plain documents whose container format is unambiguous
     *
     * ZIP based formats (docx, xlsx, odt) are deliberately absent: content
     * sniffing reports them as "application/zip" unless the magic database
     * is current, so allowing them means allowing every ZIP archive. Add
     * them explicitly if that trade-off is acceptable.
     *
     * @throws InvalidUploadConstraintsException Never - the preset is valid
     */
    public static function documents(): self
    {
        return new self([
            'pdf' => ['application/pdf'],
            'txt' => ['text/plain'],
            'csv' => ['text/csv', 'text/plain'],
        ]);
    }

    /**
     * Lowercase and validate the allow-list
     *
     * @param array<array-key, list<string>> $allowedTypes
     *
     * @return non-empty-array<array-key, non-empty-list<string>>
     *
     * @throws InvalidUploadConstraintsException If the allow-list is not usable
     */
    private function normalizeAllowedTypes(array $allowedTypes): array
    {
        if ($allowedTypes === []) {
            throw InvalidUploadConstraintsException::emptyAllowList();
        }

        $normalized = [];

        foreach ($allowedTypes as $extension => $mimeTypes) {
            // PHP coerces numeric array keys to int, so never assume a string
            $raw = (string) $extension;
            $key = strtolower(ltrim($raw, '.'));

            if (preg_match(self::EXTENSION_SEGMENT, $key) !== 1) {
                throw InvalidUploadConstraintsException::invalidExtension($raw);
            }

            $normalized[$key] = $this->normalizeMimeTypes($key, $mimeTypes);
        }

        return $normalized;
    }

    /**
     * Lowercase and validate the MIME types of one extension
     *
     * @param list<string> $mimeTypes
     *
     * @return non-empty-list<string>
     *
     * @throws InvalidUploadConstraintsException If a MIME type is not usable
     */
    private function normalizeMimeTypes(string $extension, array $mimeTypes): array
    {
        if ($mimeTypes === []) {
            throw InvalidUploadConstraintsException::emptyMimeTypeList($extension);
        }

        $normalized = [];

        foreach ($mimeTypes as $mimeType) {
            $lowered = strtolower(trim($mimeType));

            if (preg_match(self::MIME_TYPE, $lowered) !== 1) {
                throw InvalidUploadConstraintsException::invalidMimeType($mimeType);
            }

            $normalized[] = $lowered;
        }

        return $normalized;
    }
}
