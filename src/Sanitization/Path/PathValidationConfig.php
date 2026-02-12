<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Path;

/**
 * Configuration for path validation
 */
final readonly class PathValidationConfig
{
    /**
     * @param string|null $basePath Base directory paths must be within (null = no restriction)
     * @param bool $allowDotFiles Allow hidden files (starting with .)
     * @param bool $allowSymlinks Allow symbolic links
     * @param bool $normalizePath Normalize path before validation
     * @param list<string> $blockedExtensions File extensions to block
     */
    public function __construct(
        public ?string $basePath = null,
        public bool $allowDotFiles = false,
        public bool $allowSymlinks = false,
        public bool $normalizePath = true,
        public array $blockedExtensions = [],
    ) {
    }

    /**
     * Create with base path restriction
     */
    public function withBasePath(string $basePath): self
    {
        return new self(
            $basePath,
            $this->allowDotFiles,
            $this->allowSymlinks,
            $this->normalizePath,
            $this->blockedExtensions
        );
    }

    /**
     * Create with dot files allowed
     */
    public function withDotFiles(): self
    {
        return new self(
            $this->basePath,
            true,
            $this->allowSymlinks,
            $this->normalizePath,
            $this->blockedExtensions
        );
    }

    /**
     * Create with symlinks allowed
     */
    public function withSymlinks(): self
    {
        return new self(
            $this->basePath,
            $this->allowDotFiles,
            true,
            $this->normalizePath,
            $this->blockedExtensions
        );
    }

    /**
     * Create with blocked extensions
     *
     * @param list<string> $extensions Extensions to block (without dot)
     */
    public function withBlockedExtensions(array $extensions): self
    {
        return new self(
            $this->basePath,
            $this->allowDotFiles,
            $this->allowSymlinks,
            $this->normalizePath,
            $extensions
        );
    }

    /**
     * Create strict configuration
     */
    public static function strict(string $basePath): self
    {
        return new self(
            basePath: $basePath,
            allowDotFiles: false,
            allowSymlinks: false,
            normalizePath: true,
            blockedExtensions: ['php', 'phtml', 'php3', 'php4', 'php5', 'phar']
        );
    }
}
