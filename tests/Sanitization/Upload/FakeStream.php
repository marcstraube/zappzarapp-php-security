<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Upload;

use Psr\Http\Message\StreamInterface;
use RuntimeException;

/**
 * A PSR-7 stream with fully controllable read behaviour
 *
 * Chunk size, seekability and the "never reports EOF" case are all
 * configurable so the bounded read loop can be exercised exhaustively.
 */
final class FakeStream implements StreamInterface
{
    private int $position = 0;

    /**
     * @param string $content The stream content
     * @param int $chunkSize Maximum bytes returned per read() call
     * @param bool $seekable Whether rewind() is allowed
     * @param bool $neverEof Report eof() as false even when exhausted
     * @param bool $reportSize Whether getSize() reports a size at all
     */
    public function __construct(
        private readonly string $content,
        private readonly int $chunkSize = 8192,
        private readonly bool $seekable = true,
        private readonly bool $neverEof = false,
        private readonly bool $reportSize = true,
    ) {
    }

    public function __toString(): string
    {
        return $this->content;
    }

    public function close(): void
    {
        $this->position = strlen($this->content);
    }

    /**
     * PSR-7 returns the underlying resource here, and PHP has no type for a
     * resource - hence no return type, matching StreamInterface itself.
     *
     * @return resource|null
     */
    public function detach()
    {
        return null;
    }

    public function getSize(): ?int
    {
        return $this->reportSize ? strlen($this->content) : null;
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        if ($this->neverEof) {
            return false;
        }

        return $this->position >= strlen($this->content);
    }

    public function isSeekable(): bool
    {
        return $this->seekable;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        if (!$this->seekable) {
            throw new RuntimeException('Stream is not seekable');
        }

        $this->position = $offset;
    }

    public function rewind(): void
    {
        $this->seek(0);
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new RuntimeException('Stream is not writable');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read(int $length): string
    {
        $chunk = substr($this->content, $this->position, min($length, $this->chunkSize));

        $this->position += strlen($chunk);

        return $chunk;
    }

    public function getContents(): string
    {
        $remaining = substr($this->content, $this->position);

        $this->position = strlen($this->content);

        return $remaining;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function getMetadata(?string $key = null): ?array
    {
        return $key === null ? [] : null;
    }
}
