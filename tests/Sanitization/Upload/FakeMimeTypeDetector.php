<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use Zappzarapp\Security\Sanitization\Upload\MimeTypeDetectorInterface;

/**
 * Reports a fixed MIME type, including the "detection failed" case
 */
final readonly class FakeMimeTypeDetector implements MimeTypeDetectorInterface
{
    public function __construct(private ?string $mimeType)
    {
    }

    public function detectFromFile(string $path): ?string
    {
        return $this->mimeType;
    }

    public function detectFromBuffer(string $buffer): ?string
    {
        return $this->mimeType;
    }
}
