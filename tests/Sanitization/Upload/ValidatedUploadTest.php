<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Upload\ValidatedUpload;

#[CoversClass(ValidatedUpload::class)]
final class ValidatedUploadTest extends TestCase
{
    #[Test]
    public function testExposesEveryValidatedField(): void
    {
        $upload = new ValidatedUpload('photo.jpg', 'jpg', 'image/jpeg', 1024);

        $this->assertSame('photo.jpg', $upload->filename);
        $this->assertSame('jpg', $upload->extension);
        $this->assertSame('image/jpeg', $upload->mimeType);
        $this->assertSame(1024, $upload->sizeBytes);
    }
}
