<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Upload;

/**
 * Detects the real MIME type of a file from its content
 *
 * The client supplied Content-Type of a multipart part is never an input
 * here - it is chosen by the uploader and therefore worthless.
 */
interface MimeTypeDetectorInterface
{
    /**
     * Detect the MIME type of a file on disk
     *
     * @param string $path Path to the file
     *
     * @return string|null The detected type, or null when detection failed
     */
    public function detectFromFile(string $path): ?string;

    /**
     * Detect the MIME type of an in-memory buffer
     *
     * @param string $buffer The file content
     *
     * @return string|null The detected type, or null when detection failed
     */
    public function detectFromBuffer(string $buffer): ?string;
}
