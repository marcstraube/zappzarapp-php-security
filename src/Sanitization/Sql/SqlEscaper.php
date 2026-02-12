<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sanitization\Sql;

use InvalidArgumentException;

/**
 * SQL escaper for identifiers and LIKE patterns
 *
 * WARNING: This class is NOT for escaping query values.
 * Always use prepared statements with bound parameters for values.
 *
 * Use this class only for:
 * - Dynamic table/column names (via validateIdentifier with whitelist)
 * - LIKE pattern wildcards
 */
final readonly class SqlEscaper
{
    /**
     * Escape LIKE pattern special characters
     *
     * @param string $value The value to escape for LIKE
     * @param string $escapeChar The escape character to use
     *
     * @return string The escaped value (still needs parameter binding!)
     *
     * @psalm-taint-escape sql
     */
    public function escapeLike(string $value, string $escapeChar = '\\'): string
    {
        // Escape the escape character first
        $escaped = str_replace($escapeChar, $escapeChar . $escapeChar, $value);

        // Escape LIKE wildcards
        $escaped = str_replace('%', $escapeChar . '%', $escaped);

        return str_replace('_', $escapeChar . '_', $escaped);
    }

    /**
     * Validate an identifier name
     *
     * Returns true if the identifier is safe (alphanumeric + underscore only).
     * Prefer using this validation over dynamic quoting when possible.
     */
    public function isValidIdentifier(string $identifier): bool
    {
        // Allow only alphanumeric and underscore, must start with letter or underscore
        return preg_match('/^[a-zA-Z_]\w*$/', $identifier) === 1;
    }

    /**
     * Validate and return identifier, throwing if invalid
     *
     * Use this for a whitelist approach instead of quoting.
     *
     * @param string $identifier The identifier to validate
     * @param list<string> $allowed List of allowed identifiers
     *
     * @throws InvalidArgumentException If identifier is not in allowed list
     *
     * @psalm-taint-escape sql
     */
    public function validateIdentifier(string $identifier, array $allowed): string
    {
        if (!in_array($identifier, $allowed, true)) {
            throw new InvalidArgumentException(sprintf(
                'Invalid identifier "%s". Allowed: %s',
                $identifier,
                implode(', ', $allowed)
            ));
        }

        return $identifier;
    }
}
