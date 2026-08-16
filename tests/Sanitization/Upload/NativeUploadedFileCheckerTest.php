<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Upload\NativeUploadedFileChecker;

#[CoversClass(NativeUploadedFileChecker::class)]
final class NativeUploadedFileCheckerTest extends TestCase
{
    #[Test]
    public function testAMissingPathIsNotAnUploadedFile(): void
    {
        $checker = new NativeUploadedFileChecker();

        $this->assertFalse($checker->isUploadedFile('/nonexistent/upload.tmp'));
    }

    #[Test]
    public function testAnOrdinaryFileIsNotAnUploadedFile(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'zzp-upload-');
        $this->assertIsString($path);

        try {
            $checker = new NativeUploadedFileChecker();

            // Only PHP itself can create a file that is_uploaded_file()
            // accepts, so any file the test creates must be rejected
            $this->assertFalse($checker->isUploadedFile($path));
        } finally {
            unlink($path);
        }
    }
}
