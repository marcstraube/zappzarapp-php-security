<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use Zappzarapp\Security\Sanitization\Upload\UploadedFileCheckerInterface;

/**
 * Stands in for is_uploaded_file(), which is always false under a test runner
 */
final readonly class FakeUploadedFileChecker implements UploadedFileCheckerInterface
{
    public function __construct(private bool $result = true)
    {
    }

    public function isUploadedFile(string $path): bool
    {
        return $this->result;
    }
}
