<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Upload;

/**
 * The outcome of a successful upload validation
 *
 * Every field has passed validation: the filename is a bare name over
 * `[A-Za-z0-9._-]` (or Unicode letters when opted in), the extension is
 * an allow-list key, the MIME type was detected from the content and the
 * size is the real byte count - not the one the client reported.
 */
final readonly class ValidatedUpload
{
    /**
     * @param string $filename Sanitized filename, without directory components
     * @param string $extension The matched allow-list extension, lowercase
     * @param string $mimeType The MIME type detected from the content
     * @param int $sizeBytes The real size of the content in bytes
     */
    public function __construct(
        public string $filename,
        public string $extension,
        public string $mimeType,
        public int $sizeBytes,
    ) {
    }
}
