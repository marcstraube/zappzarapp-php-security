<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets\Exception;

use RuntimeException;

/**
 * Exception thrown when a secret exists but cannot be loaded
 */
final class SecretLoadException extends RuntimeException
{
    /**
     * Create for a secret that exists but is empty
     *
     * An empty secret is treated as a configuration error, not as a missing
     * secret, so it surfaces immediately instead of silently falling through
     * to another source.
     */
    public static function emptySecret(string $name, string $source): self
    {
        return new self(sprintf(
            'Secret "%s" in source "%s" is empty',
            $name,
            $source
        ));
    }

    /**
     * Create for a secret file that exists but cannot be read
     */
    public static function unreadableFile(string $path): self
    {
        return new self(sprintf(
            'Secret file "%s" exists but cannot be read (check file permissions)',
            $path
        ));
    }
}
