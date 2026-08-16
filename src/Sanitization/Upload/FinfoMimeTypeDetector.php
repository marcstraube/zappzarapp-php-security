<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Upload;

use finfo;

/**
 * MIME type detection via libmagic (ext-fileinfo)
 *
 * Detection is content based: it reads the magic bytes of the file, so a
 * PHP script renamed to `avatar.jpg` is reported as `text/x-php`, not as
 * `image/jpeg`.
 *
 * Sniffing has limits and is one half of the check, not the whole check.
 * Formats that are ZIP containers (docx, xlsx, odt, jar) all look like
 * `application/zip`, and polyglot files - a valid GIF whose trailing
 * bytes are PHP - are reported as the leading format. The extension
 * allow-list and never executing uploaded content are what close that
 * gap; see the module documentation.
 */
final readonly class FinfoMimeTypeDetector implements MimeTypeDetectorInterface
{
    /**
     * Detect the MIME type of a file on disk
     *
     * @param string $path Path to the file
     *
     * @return string|null The detected type, or null when detection failed
     */
    public function detectFromFile(string $path): ?string
    {
        // Checked up front so a missing file returns null instead of
        // raising a warning that a strict error handler would escalate
        if (!is_file($path)) {
            return null;
        }

        $finfo    = new finfo(FILEINFO_MIME_TYPE);
        $detected = $finfo->file($path);

        return $detected === false ? null : $detected;
    }

    /**
     * Detect the MIME type of an in-memory buffer
     *
     * @param string $buffer The file content
     *
     * @return string|null The detected type, or null when detection failed
     */
    public function detectFromBuffer(string $buffer): ?string
    {
        $finfo    = new finfo(FILEINFO_MIME_TYPE);
        $detected = $finfo->buffer($buffer);

        return $detected === false ? null : $detected;
    }
}
