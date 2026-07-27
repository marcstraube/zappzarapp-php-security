<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets;

use Zappzarapp\Security\Secrets\Exception\InvalidSecretNameException;

/**
 * Validated secret name
 *
 * Secret names are used to build file paths (e.g. /run/secrets/<name>) and
 * environment variable names, so validation is strict by design:
 *
 * - Only `A-Z`, `a-z`, `0-9`, `.`, `_` and `-` are allowed
 * - The first character must be alphanumeric (rejects hidden files, `.` and `..`)
 * - Path separators and control characters are rejected (path traversal,
 *   header/log injection)
 * - Maximum length is 255 characters (filesystem name limit)
 */
final readonly class SecretName
{
    /**
     * Maximum secret name length (common filesystem name limit)
     */
    public const int MAX_LENGTH = 255;

    /**
     * Allowed name format: alphanumeric first character, then alphanumerics,
     * dots, underscores and hyphens
     */
    private const string VALID_PATTERN = '/^[A-Za-z0-9][A-Za-z0-9._-]*\z/';

    /**
     * @throws InvalidSecretNameException If the name is empty, too long, or contains invalid characters
     */
    public function __construct(
        public string $value,
    ) {
        if ($this->value === '') {
            throw InvalidSecretNameException::emptyName();
        }

        if (strlen($this->value) > self::MAX_LENGTH) {
            throw InvalidSecretNameException::tooLong(self::MAX_LENGTH);
        }

        if (preg_match(self::VALID_PATTERN, $this->value) !== 1) {
            throw InvalidSecretNameException::invalidCharacters();
        }
    }

    /**
     * Create from a string
     *
     * @throws InvalidSecretNameException If the name is empty, too long, or contains invalid characters
     */
    public static function fromString(string $value): self
    {
        return new self($value);
    }

    /**
     * Get the environment variable form of this name
     *
     * Converts to uppercase and replaces dots and hyphens with underscores,
     * following the common convention (e.g. "db.password" -> "DB_PASSWORD").
     */
    public function toEnvVariableName(string $prefix = ''): string
    {
        return $prefix . strtoupper(str_replace(['.', '-'], '_', $this->value));
    }
}
