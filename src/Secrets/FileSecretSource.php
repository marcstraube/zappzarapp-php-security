<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets;

use Override;
use Zappzarapp\Security\Secrets\Exception\SecretLoadException;

/**
 * Secret source reading Docker-style secret files
 *
 * Looks up secrets below a base path (default: /run/secrets, the Docker
 * secrets mount point), trying both "<name>" and "<name>.txt". A single
 * trailing newline is trimmed, following the common file convention; all
 * other whitespace is preserved as part of the secret.
 *
 * Path traversal is prevented by SecretName validation - names cannot
 * contain path separators or start with a dot.
 *
 * ## Usage
 *
 * ```php
 * $source = new FileSecretSource();          // /run/secrets
 * $source = new FileSecretSource('/etc/app/secrets');
 * ```
 */
final readonly class FileSecretSource implements SecretSourceInterface
{
    /**
     * Default Docker secrets mount point
     */
    public const string DEFAULT_BASE_PATH = '/run/secrets';

    private string $basePath;

    public function __construct(string $basePath = self::DEFAULT_BASE_PATH)
    {
        $this->basePath = rtrim($basePath, '/');
    }

    #[Override]
    public function fetch(SecretName $name): ?string
    {
        foreach ($this->candidatePaths($name) as $path) {
            if (!is_file($path)) {
                continue;
            }

            return $this->readFile($path);
        }

        return null;
    }

    #[Override]
    public function describe(): string
    {
        return sprintf('file:%s', $this->basePath);
    }

    /**
     * Candidate file paths for a secret name, in lookup order
     *
     * @return list<string>
     */
    private function candidatePaths(SecretName $name): array
    {
        return [
            sprintf('%s/%s', $this->basePath, $name->value),
            sprintf('%s/%s.txt', $this->basePath, $name->value),
        ];
    }

    /**
     * Read a secret file and trim the trailing newline
     *
     * @throws SecretLoadException If the file exists but cannot be read
     */
    private function readFile(string $path): string
    {
        if (!is_readable($path)) {
            throw SecretLoadException::unreadableFile($path);
        }

        $content = file_get_contents($path);

        // @codeCoverageIgnoreStart
        if ($content === false) {
            // Race between is_readable() and the read; not reproducible in tests.
            throw SecretLoadException::unreadableFile($path);
        }

        // @codeCoverageIgnoreEnd

        return $this->trimTrailingNewline($content);
    }

    /**
     * Trim exactly one trailing newline (file convention)
     *
     * Editors and `echo` append a trailing newline to secret files. Only a
     * single trailing "\n" or "\r\n" is removed - everything else is
     * treated as part of the secret.
     */
    private function trimTrailingNewline(string $content): string
    {
        if (str_ends_with($content, "\r\n")) {
            return substr($content, 0, -2);
        }

        if (str_ends_with($content, "\n")) {
            return substr($content, 0, -1);
        }

        return $content;
    }
}
