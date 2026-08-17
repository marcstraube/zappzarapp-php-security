<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UploadedFileInterface;
use RuntimeException;

/**
 * A PSR-7 uploaded file backed by an in-memory stream
 */
final readonly class FakeUploadedFile implements UploadedFileInterface
{
    public function __construct(
        private StreamInterface $stream,
        private ?string $clientFilename = 'upload.txt',
        private int $error = UPLOAD_ERR_OK,
        private ?int $size = null,
        private ?string $clientMediaType = 'text/plain',
    ) {
    }

    public function getStream(): StreamInterface
    {
        return $this->stream;
    }

    public function moveTo(string $targetPath): void
    {
        throw new RuntimeException('Not implemented');
    }

    public function getSize(): ?int
    {
        return $this->size;
    }

    public function getError(): int
    {
        return $this->error;
    }

    public function getClientFilename(): ?string
    {
        return $this->clientFilename;
    }

    public function getClientMediaType(): ?string
    {
        return $this->clientMediaType;
    }
}
