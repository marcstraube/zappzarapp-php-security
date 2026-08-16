<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Upload;

/**
 * The production check, backed by is_uploaded_file()
 *
 * Without it, a `tmp_name` forged into `$_FILES` - through a second
 * vulnerability such as a request parsing bug or an unserialize gadget -
 * would let an attacker point the validator at `/etc/passwd` and have the
 * application store or serve it.
 */
final readonly class NativeUploadedFileChecker implements UploadedFileCheckerInterface
{
    /**
     * Whether the path was created by an HTTP file upload
     *
     * @param string $path The temporary file path from $_FILES
     */
    public function isUploadedFile(string $path): bool
    {
        return is_uploaded_file($path);
    }
}
