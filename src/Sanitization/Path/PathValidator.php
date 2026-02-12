<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Path;

use Zappzarapp\Security\Logging\SecurityLoggerInterface;
use Zappzarapp\Security\Sanitization\Exception\PathTraversalException;

/**
 * Path validator with traversal detection
 *
 * Detects and prevents:
 * - Directory traversal (../, ..\)
 * - Null byte injection
 * - Encoded traversal sequences
 * - Paths outside allowed directory
 *
 * SECURITY NOTE: Path validation is inherently subject to TOCTOU
 * (Time-of-Check-Time-of-Use) race conditions. Between validation
 * and actual file operations, the filesystem state may change.
 * For critical operations, use additional safeguards:
 * - File locking (flock)
 * - Atomic operations where possible
 * - Chroot/containerization at infrastructure level
 *
 * @see https://cwe.mitre.org/data/definitions/367.html
 */
final readonly class PathValidator
{
    public function __construct(
        private PathValidationConfig $config = new PathValidationConfig(),
        private ?SecurityLoggerInterface $logger = null,
    ) {
    }

    /**
     * Validate a path
     *
     * @param string $path The path to validate
     *
     * @throws PathTraversalException If path is unsafe
     */
    public function validate(string $path): void
    {
        // Check for null bytes
        if (str_contains($path, "\0")) {
            $this->logTraversalAttempt($path, 'null_byte');
            throw PathTraversalException::nullByteDetected($path);
        }

        // Decode and check for traversal
        $decoded = $this->decodeEncodedSequences($path);
        if ($this->containsTraversal($decoded)) {
            $this->logTraversalAttempt($path, 'traversal_sequence');
            throw PathTraversalException::traversalDetected($path);
        }

        // Check against base path if configured
        if ($this->config->basePath !== null) {
            $this->validateAgainstBasePath($path);
        }

        // Check for dot files
        if (!$this->config->allowDotFiles && $this->hasDotFile($path)) {
            $this->logTraversalAttempt($path, 'dot_file');
            throw PathTraversalException::traversalDetected($path);
        }

        // Check for blocked extensions
        if ($this->hasBlockedExtension($path)) {
            $this->logTraversalAttempt($path, 'blocked_extension');
            throw PathTraversalException::traversalDetected($path);
        }
    }

    /**
     * Log a path traversal attempt
     */
    private function logTraversalAttempt(string $path, string $reason): void
    {
        $this->logger?->alert('Path traversal attempt detected', [
            'path'      => $path,
            'reason'    => $reason,
            'base_path' => $this->config->basePath,
        ]);
    }

    /**
     * Check if path is safe without throwing
     */
    public function isSafe(string $path): bool
    {
        try {
            $this->validate($path);

            return true;
        } catch (PathTraversalException) {
            return false;
        }
    }

    /**
     * Normalize and validate a path, returning the safe path
     *
     * @throws PathTraversalException If path is unsafe
     *
     * @psalm-taint-escape file
     */
    public function normalize(string $path): string
    {
        $this->validate($path);

        if (!$this->config->normalizePath) {
            return $path;
        }

        // Normalize directory separators
        $normalized = str_replace('\\', '/', $path);

        // Remove redundant slashes
        $normalized = preg_replace('#/+#', '/', $normalized);
        if ($normalized === null) {
            return $path;
        }

        // Remove trailing slash except for root
        if ($normalized !== '/' && str_ends_with($normalized, '/')) {
            return rtrim($normalized, '/');
        }

        return $normalized;
    }

    /**
     * Check if path contains traversal sequences
     */
    private function containsTraversal(string $path): bool
    {
        // Normalize slashes for detection
        $normalized = str_replace('\\', '/', $path);

        // Check for various traversal patterns
        $patterns = [
            '../',
            '..\\',
            '/..',
            '\\..',
            '..' . chr(0),
        ];

        if (array_any($patterns, static fn(string $pattern): bool => str_contains($normalized, $pattern))) {
            return true;
        }

        // Check if path is exactly '..'
        return $normalized === '..' || str_ends_with($normalized, '/..');
    }

    /**
     * Decode common encoding schemes used in traversal attacks
     */
    private function decodeEncodedSequences(string $path): string
    {
        $decoded = $path;

        // URL decode (multiple times to catch double encoding)
        for ($i = 0; $i < 3; $i++) {
            $newDecoded = rawurldecode($decoded);
            if ($newDecoded === $decoded) {
                break;
            }

            $decoded = $newDecoded;
        }

        return $decoded;
    }

    /**
     * Validate path is within base path
     *
     * @throws PathTraversalException If path is outside base path
     */
    private function validateAgainstBasePath(string $path): void
    {
        $basePath = $this->config->basePath;
        if ($basePath === null) {
            return;
        }

        // Resolve to real path if file exists
        $realPath = realpath($path);
        $realBase = realpath($basePath);

        if ($realBase === false) {
            $this->logTraversalAttempt($path, 'outside_base_path');
            throw PathTraversalException::outsideBasePath($path, $basePath);
        }

        // If file doesn't exist, check the parent directory
        if ($realPath === false) {
            $parentDir  = dirname($path);
            $realParent = realpath($parentDir);

            if ($realParent === false || !str_starts_with($realParent, $realBase)) {
                $this->logTraversalAttempt($path, 'outside_base_path');
                throw PathTraversalException::outsideBasePath($path, $basePath);
            }

            // Check for symlinks in the path if not allowed
            if (!$this->config->allowSymlinks) {
                $this->checkSymlinksInPath($parentDir);
            }

            return;
        }

        // Check if real path starts with base path
        if (!str_starts_with($realPath, $realBase)) {
            $this->logTraversalAttempt($path, 'outside_base_path');
            throw PathTraversalException::outsideBasePath($path, $basePath);
        }

        // Check for symlinks in the path if not allowed
        // This uses lstat() to detect symlinks even after realpath() resolution
        if (!$this->config->allowSymlinks) {
            $this->checkSymlinksInPath($path);
        }
    }

    /**
     * Check for symlinks in the entire path hierarchy
     *
     * Uses is_link() (which calls lstat()) to detect symlinks at each level.
     *
     * Note: While this check reduces the attack surface, it cannot fully
     * prevent TOCTOU race conditions. For critical use cases, consider
     * using file locking or atomic operations at the application level.
     *
     * @throws PathTraversalException If a symlink is found in the path
     */
    private function checkSymlinksInPath(string $path): void
    {
        // Normalize path separators
        $normalized = str_replace('\\', '/', $path);
        $current    = $normalized;

        // Walk up the directory tree checking each component
        while (!in_array($current, ['/', '', '.'], true)) {
            if (is_link($current)) {
                $this->logTraversalAttempt($path, 'symlink_in_path');
                throw PathTraversalException::traversalDetected($path);
            }

            $parent = dirname($current);
            // Prevent infinite loop
            if ($parent === $current) {
                break;
            }

            $current = $parent;
        }
    }

    /**
     * Check if path contains a hidden (dot) file
     */
    private function hasDotFile(string $path): bool
    {
        $parts = preg_split('#[/\\\\]#', $path);
        // @codeCoverageIgnoreStart - preg_split never returns false with valid regex
        if ($parts === false) {
            return false;
        }

        // @codeCoverageIgnoreEnd

        return array_any($parts, fn(string $part): bool => $part !== '' && str_starts_with($part, '.') && $part !== '.' && $part !== '..');
    }

    /**
     * Check if path has a blocked extension
     */
    private function hasBlockedExtension(string $path): bool
    {
        if ($this->config->blockedExtensions === []) {
            return false;
        }

        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        return in_array($extension, $this->config->blockedExtensions, true);
    }
}
