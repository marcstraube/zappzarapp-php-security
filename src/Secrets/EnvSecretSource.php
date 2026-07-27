<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets;

use Override;
use Zappzarapp\Security\Secrets\Exception\InvalidEnvPrefixException;

/**
 * Secret source reading environment variables
 *
 * Environment variables are visible to the whole process (and often to
 * child processes, /proc, and error reports), so this source is an explicit
 * opt-in fallback for environments without file-based secrets - it is not
 * part of any default configuration.
 *
 * The secret name is converted to the conventional environment variable
 * form: uppercase, with dots and hyphens replaced by underscores
 * (e.g. "db.password" -> "DB_PASSWORD"), plus an optional prefix.
 *
 * ## Usage
 *
 * ```php
 * $source = new EnvSecretSource();          // db_password -> DB_PASSWORD
 * $source = new EnvSecretSource('APP_');    // db_password -> APP_DB_PASSWORD
 * ```
 */
final readonly class EnvSecretSource implements SecretSourceInterface
{
    /**
     * Allowed prefix format: uppercase letters, digits and underscores,
     * starting with a letter (empty prefix allowed)
     */
    private const string PREFIX_PATTERN = '/^([A-Z][A-Z0-9_]*)?\z/';

    /**
     * @throws InvalidEnvPrefixException If the prefix contains invalid characters
     */
    public function __construct(
        private string $prefix = '',
    ) {
        if (preg_match(self::PREFIX_PATTERN, $this->prefix) !== 1) {
            throw InvalidEnvPrefixException::invalidCharacters();
        }
    }

    #[Override]
    public function fetch(SecretName $name): ?string
    {
        $value = getenv($name->toEnvVariableName($this->prefix));

        if ($value === false) {
            return null;
        }

        return $value;
    }

    #[Override]
    public function describe(): string
    {
        if ($this->prefix === '') {
            return 'env';
        }

        return sprintf('env:%s*', $this->prefix);
    }
}
