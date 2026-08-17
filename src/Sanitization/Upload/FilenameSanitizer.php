<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native ext-intl class, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Upload;

use Normalizer;
use Zappzarapp\Security\Sanitization\Exception\InvalidFilenameException;

/**
 * Turns a client supplied filename into a safe storage filename
 *
 * A client filename is fully attacker controlled. It reaches the
 * filesystem, log files and - via Content-Disposition - HTTP headers, so
 * it is treated as hostile input throughout.
 *
 * The sanitizer rejects what can never be legitimate and transforms what
 * merely needs to be made safe:
 *
 * | Input                       | Result                              |
 * | --------------------------- | ----------------------------------- |
 * | NUL byte, control character | rejected                            |
 * | invalid UTF-8               | rejected                            |
 * | bidi override, zero width   | rejected (`gpj.\u{202E}exe` tricks) |
 * | `..`, `.`                   | rejected                            |
 * | Windows device name         | rejected                            |
 * | longer than the limit       | rejected                            |
 * | directory components        | stripped (`a/b/c.png` -> `c.png`)   |
 * | leading dots                | stripped (no hidden files)          |
 * | trailing dots and spaces    | stripped (Windows drops them)       |
 * | everything else unsafe      | replaced with `_`                   |
 *
 * The result is always a bare filename over `[A-Za-z0-9._-]`, which is
 * safe in a path, in a shell word, in a header value and in a log line.
 * Unicode filenames are available as an explicit opt-in and are then
 * NFC-normalized and restricted to letters, marks and digits.
 *
 * ## Usage
 *
 * ```php
 * $sanitizer = new FilenameSanitizer();
 *
 * $sanitizer->sanitize('../../etc/passwd');   // "passwd"
 * $sanitizer->sanitize('My Report (1).pdf');  // "My_Report__1_.pdf"
 * $sanitizer->sanitize('.htaccess');          // "htaccess"
 * ```
 */
final readonly class FilenameSanitizer
{
    /**
     * Default filename length limit in bytes
     *
     * 255 is the per-component limit of ext4, XFS, APFS and NTFS.
     */
    public const int DEFAULT_MAX_LENGTH = 255;

    /**
     * ASCII control characters, including the NUL byte
     */
    private const string CONTROL_CHARACTERS = '/[\x00-\x1F\x7F]/';

    /**
     * Zero-width and bidirectional formatting characters
     *
     * A right-to-left override turns "exe.txt" into a name that renders
     * as "txt.exe" - or the other way round - in every file manager.
     */
    private const string UNSAFE_UNICODE = '/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]/u';

    /**
     * Characters that are not allowed in an ASCII filename
     */
    private const string UNSAFE_ASCII = '/[^A-Za-z0-9._-]/';

    /**
     * Characters that are not allowed in a Unicode filename
     */
    private const string UNSAFE_UNICODE_REST = '/[^\p{L}\p{M}\p{N}._-]/u';

    /**
     * Windows device names, which are reserved in every directory
     */
    private const string RESERVED_NAMES = '/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i';

    /**
     * @param int $maxLength Maximum filename length in bytes
     * @param bool $allowUnicode Keep Unicode letters, marks and digits instead of replacing them
     */
    public function __construct(
        private int $maxLength = self::DEFAULT_MAX_LENGTH,
        private bool $allowUnicode = false,
    ) {
    }

    /**
     * Sanitize a client supplied filename
     *
     * @param string $filename The raw client filename
     *
     * @return string A bare filename without directory components
     *
     * @throws InvalidFilenameException If no safe filename can be derived
     */
    public function sanitize(string $filename): string
    {
        $this->rejectHostileCharacters($filename);

        $normalized = $this->normalizeUnicode($filename);

        if (preg_match(self::UNSAFE_UNICODE, $normalized) === 1) {
            throw InvalidFilenameException::unsafeUnicode();
        }

        $base = $this->stripDirectoryComponents($normalized);

        if ($base === '.' || $base === '..') {
            throw InvalidFilenameException::traversal();
        }

        // Windows silently drops trailing dots and spaces, so "evil.php."
        // would land on disk as "evil.php"
        $base = rtrim($base, ' .');

        // A leading dot creates a hidden file (".htaccess", ".bashrc")
        $base = ltrim($base, '.');

        $base = $this->replaceUnsafeCharacters($base);

        if ($base === '') {
            throw InvalidFilenameException::emptyResult();
        }

        $this->rejectReservedName($base);

        $length = strlen($base);

        if ($length > $this->maxLength) {
            throw InvalidFilenameException::tooLong($length, $this->maxLength);
        }

        return $base;
    }

    /**
     * Reject characters that can never appear in a legitimate filename
     *
     * These are not stripped: a name such as "shell.php\0.jpg" is an
     * attack, not a typo, and silently repairing it would hide it.
     *
     * @throws InvalidFilenameException If the filename is hostile
     */
    private function rejectHostileCharacters(string $filename): void
    {
        if (str_contains($filename, "\0")) {
            throw InvalidFilenameException::nullByte();
        }

        if (preg_match(self::CONTROL_CHARACTERS, $filename) === 1) {
            throw InvalidFilenameException::controlCharacter();
        }

        if (!mb_check_encoding($filename, 'UTF-8')) {
            throw InvalidFilenameException::invalidEncoding();
        }
    }

    /**
     * Normalize to NFC so visually identical names compare identically
     */
    private function normalizeUnicode(string $filename): string
    {
        // ext-intl is optional: without it, and when normalization
        // fails, the name is carried through unchanged - the allow-list
        // below is what keeps it safe either way
        $normalized = function_exists('normalizer_normalize')
            ? Normalizer::normalize($filename, Normalizer::FORM_C)
            : $filename;

        return $normalized === false ? $filename : $normalized;
    }

    /**
     * Keep only the last path component
     *
     * Both separators are honoured: a Windows client may send
     * "C:\Users\bob\evil.php" and a POSIX server must not keep any of it.
     */
    private function stripDirectoryComponents(string $filename): string
    {
        $unified  = str_replace('\\', '/', $filename);
        $position = strrpos($unified, '/');

        if ($position === false) {
            return $unified;
        }

        return substr($unified, $position + 1);
    }

    /**
     * Replace every character outside the allowed set with an underscore
     */
    private function replaceUnsafeCharacters(string $base): string
    {
        $pattern = $this->allowUnicode ? self::UNSAFE_UNICODE_REST : self::UNSAFE_ASCII;

        return (string) preg_replace($pattern, '_', $base);
    }

    /**
     * Reject Windows device names such as CON, NUL or COM1
     *
     * Windows resolves them in every directory and regardless of the
     * extension, so "nul.txt" is still the null device.
     *
     * @throws InvalidFilenameException If the stem is a reserved name
     */
    private function rejectReservedName(string $base): void
    {
        $stem = strstr($base, '.', true);

        if ($stem === false) {
            $stem = $base;
        }

        if (preg_match(self::RESERVED_NAMES, $stem) === 1) {
            throw InvalidFilenameException::reservedName($base);
        }
    }
}
