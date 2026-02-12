<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Cookie;

use Zappzarapp\Security\Cookie\Exception\InvalidCookieNameException;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieValueException;

/**
 * RFC 6265 compliant cookie validator with cookie prefix support
 *
 * Validates cookie names and values according to RFC 6265.
 * Also validates cookie prefix constraints (__Host- and __Secure-).
 *
 * ## Cookie Prefixes (draft-ietf-httpbis-rfc6265bis)
 *
 * - `__Host-` prefix requires:
 *   - Secure flag must be true
 *   - Path must be "/"
 *   - Domain must be empty (omitted)
 *
 * - `__Secure-` prefix requires:
 *   - Secure flag must be true
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6265
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis
 */
final class CookieValidator
{
    /**
     * Cookie prefix for host-bound cookies
     */
    public const string PREFIX_HOST = '__Host-';

    /**
     * Cookie prefix for secure-only cookies
     */
    public const string PREFIX_SECURE = '__Secure-';

    /**
     * Maximum cookie size (4KB is typical browser limit)
     */
    public const int MAX_VALUE_LENGTH = 4096;

    /**
     * Characters not allowed in cookie names (RFC 6265)
     * CTLs, separators: ( ) < > @ , ; : \ " / [ ] ? = { } SP HT
     */
    private const string NAME_INVALID_CHARS = "()<>@,;:\\\"/[]?={} \t\r\n";

    /**
     * Characters not allowed in cookie values (RFC 6265)
     */
    private const string VALUE_INVALID_CHARS = " \",;\\\r\n";

    /**
     * Validate cookie name
     *
     * @throws InvalidCookieNameException If name is invalid
     */
    public function validateName(string $name): void
    {
        if ($name === '') {
            throw InvalidCookieNameException::emptyName();
        }

        // Check for invalid characters
        for ($i = 0; $i < strlen($name); $i++) {
            $char = $name[$i];
            $ord  = ord($char);

            // Control characters (0-31, 127)
            if ($ord < 32 || $ord === 127) {
                throw InvalidCookieNameException::invalidCharacter($name, sprintf('\\x%02X', $ord));
            }

            // Separator characters
            if (str_contains(self::NAME_INVALID_CHARS, $char)) {
                throw InvalidCookieNameException::invalidCharacter($name, $char);
            }
        }
    }

    /**
     * Validate cookie value
     *
     * @throws InvalidCookieValueException If value is invalid
     */
    public function validateValue(string $value): void
    {
        // Check length
        if (strlen($value) > self::MAX_VALUE_LENGTH) {
            throw InvalidCookieValueException::tooLong(strlen($value), self::MAX_VALUE_LENGTH);
        }

        // Check for invalid characters
        for ($i = 0; $i < strlen($value); $i++) {
            $char = $value[$i];
            $ord  = ord($char);

            // Control characters (0-31, 127) except HT (9)
            if (($ord < 32 && $ord !== 9) || $ord === 127) {
                throw InvalidCookieValueException::invalidCharacter($value, sprintf('\\x%02X', $ord));
            }

            // Separator characters
            if (str_contains(self::VALUE_INVALID_CHARS, $char)) {
                throw InvalidCookieValueException::invalidCharacter($value, $char);
            }
        }
    }

    /**
     * Check if name is valid without throwing
     */
    public function isValidName(string $name): bool
    {
        try {
            $this->validateName($name);

            return true;
        } catch (InvalidCookieNameException) {
            return false;
        }
    }

    /**
     * Check if value is valid without throwing
     */
    public function isValidValue(string $value): bool
    {
        try {
            $this->validateValue($value);

            return true;
        } catch (InvalidCookieValueException) {
            return false;
        }
    }

    /**
     * Validate cookie prefix constraints
     *
     * @param string $name Cookie name
     * @param CookieOptions $options Cookie options to validate against
     *
     * @throws InvalidCookieNameException If prefix constraints are violated
     */
    public function validatePrefixConstraints(string $name, CookieOptions $options): void
    {
        // Check __Host- prefix (stricter)
        if (str_starts_with($name, self::PREFIX_HOST)) {
            if (!$options->secure) {
                throw InvalidCookieNameException::prefixConstraintViolation(
                    $name,
                    self::PREFIX_HOST,
                    'Secure flag must be true'
                );
            }

            if ($options->path !== '/') {
                throw InvalidCookieNameException::prefixConstraintViolation(
                    $name,
                    self::PREFIX_HOST,
                    'Path must be "/"'
                );
            }

            if ($options->domain !== '') {
                throw InvalidCookieNameException::prefixConstraintViolation(
                    $name,
                    self::PREFIX_HOST,
                    'Domain must be empty (omitted)'
                );
            }

            return;
        }

        // Check __Secure- prefix
        if (str_starts_with($name, self::PREFIX_SECURE) && !$options->secure) {
            throw InvalidCookieNameException::prefixConstraintViolation(
                $name,
                self::PREFIX_SECURE,
                'Secure flag must be true'
            );
        }
    }

    /**
     * Check if name has a cookie prefix
     */
    public function hasPrefix(string $name): bool
    {
        return str_starts_with($name, self::PREFIX_HOST)
            || str_starts_with($name, self::PREFIX_SECURE);
    }

    /**
     * Check if prefix constraints are valid without throwing
     */
    public function isValidPrefixConstraints(string $name, CookieOptions $options): bool
    {
        try {
            $this->validatePrefixConstraints($name, $options);

            return true;
        } catch (InvalidCookieNameException) {
            return false;
        }
    }
}
