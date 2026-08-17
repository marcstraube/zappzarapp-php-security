<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when upload constraints are misconfigured
 *
 * Constraints are developer-supplied configuration, so this is raised at
 * construction time - never while handling a request.
 */
final class InvalidUploadConstraintsException extends InvalidArgumentException
{
    /**
     * Create for a missing allow-list
     */
    public static function emptyAllowList(): self
    {
        return new self('Upload constraints require a non-empty extension allow-list');
    }

    /**
     * Create for an extension key that is not a plain extension
     */
    public static function invalidExtension(string $extension): self
    {
        return new self(sprintf(
            'Invalid allow-list extension "%s": expected alphanumeric segments separated by dots',
            $extension
        ));
    }

    /**
     * Create for an extension mapped to no MIME type at all
     */
    public static function emptyMimeTypeList(string $extension): self
    {
        return new self(sprintf(
            'Extension "%s" must be mapped to at least one MIME type',
            $extension
        ));
    }

    /**
     * Create for a malformed MIME type
     */
    public static function invalidMimeType(string $mimeType): self
    {
        return new self(sprintf(
            'Invalid MIME type "%s": expected "type/subtype"',
            $mimeType
        ));
    }

    /**
     * Create for a non-positive maximum size
     */
    public static function invalidMaxSize(int $maxSizeBytes): self
    {
        return new self(sprintf(
            'Maximum upload size must be at least 1 byte, got %d',
            $maxSizeBytes
        ));
    }

    /**
     * Create for a non-positive maximum filename length
     */
    public static function invalidMaxFilenameLength(int $maxFilenameLength): self
    {
        return new self(sprintf(
            'Maximum filename length must be at least 1 byte, got %d',
            $maxFilenameLength
        ));
    }
}
