<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when an uploaded filename cannot be made safe
 *
 * The messages deliberately never embed the raw client filename: it is
 * attacker controlled and would otherwise carry control characters into
 * logs and headers. Only already-validated values are interpolated.
 */
final class InvalidFilenameException extends InvalidArgumentException
{
    /**
     * Create for a filename containing a NUL byte
     */
    public static function nullByte(): self
    {
        return new self('Filename contains a NUL byte');
    }

    /**
     * Create for a filename containing ASCII control characters
     */
    public static function controlCharacter(): self
    {
        return new self('Filename contains control characters');
    }

    /**
     * Create for a filename that is not valid UTF-8
     */
    public static function invalidEncoding(): self
    {
        return new self('Filename is not valid UTF-8');
    }

    /**
     * Create for a filename containing bidirectional or zero-width characters
     */
    public static function unsafeUnicode(): self
    {
        return new self('Filename contains bidirectional or zero-width characters');
    }

    /**
     * Create for a filename that is a traversal sequence
     */
    public static function traversal(): self
    {
        return new self('Filename is a directory traversal sequence');
    }

    /**
     * Create for a filename with no usable characters left
     */
    public static function emptyResult(): self
    {
        return new self('Filename contains no usable characters');
    }

    /**
     * Create for a Windows reserved device name
     *
     * @param string $name The sanitized name (safe character set only)
     */
    public static function reservedName(string $name): self
    {
        return new self(sprintf('Filename "%s" is a reserved device name', $name));
    }

    /**
     * Create for a filename exceeding the length limit
     */
    public static function tooLong(int $length, int $maxLength): self
    {
        return new self(sprintf(
            'Filename is %d bytes long, the maximum is %d',
            $length,
            $maxLength
        ));
    }
}
