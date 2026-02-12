<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Exception;

use RuntimeException;

/**
 * Exception thrown when path traversal is detected
 */
final class PathTraversalException extends RuntimeException
{
    /**
     * Create for path traversal attempt
     */
    public static function traversalDetected(string $path): self
    {
        return new self(sprintf(
            'Path traversal detected in: %s',
            $path
        ));
    }

    /**
     * Create for null byte injection attempt
     */
    public static function nullByteDetected(string $path): self
    {
        return new self(sprintf(
            'Null byte detected in path: %s',
            str_replace("\0", '\\0', $path)
        ));
    }

    /**
     * Create for path outside allowed directory
     */
    public static function outsideBasePath(string $path, string $basePath): self
    {
        return new self(sprintf(
            'Path "%s" is outside allowed directory "%s"',
            $path,
            $basePath
        ));
    }
}
