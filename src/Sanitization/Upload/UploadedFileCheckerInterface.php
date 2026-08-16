<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Upload;

/**
 * Decides whether a temporary path really came from an HTTP upload
 *
 * Injected rather than called directly so the check stays unit testable:
 * PHP only ever reports true for paths it created itself while handling
 * a multipart request, which never happens under a test runner.
 */
interface UploadedFileCheckerInterface
{
    /**
     * Whether the path was created by an HTTP file upload
     *
     * @param string $path The temporary file path from $_FILES
     */
    public function isUploadedFile(string $path): bool;
}
