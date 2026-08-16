<?php

declare(strict_types=1);

namespace Zappzarapp\Security\SignedUrl\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a URL cannot be signed or verified because it is
 * malformed or violates the signing rules
 *
 * Covers every structural failure: verification never falls through to a
 * PHP warning or error, no matter how mangled the attacker-controlled URL
 * string is.
 */
final class InvalidUrlException extends InvalidArgumentException
{
    /**
     * Create for a URL containing control characters (header injection guard)
     */
    public static function containsControlCharacters(): self
    {
        return new self('URL must not contain control characters');
    }

    /**
     * Create for a URL that parse_url() cannot parse
     */
    public static function malformed(): self
    {
        return new self('URL cannot be parsed');
    }

    /**
     * Create for a URL without a scheme
     */
    public static function missingScheme(): self
    {
        return new self('URL must be absolute - the scheme is missing');
    }

    /**
     * Create for a scheme other than http or https
     */
    public static function unsupportedScheme(string $scheme): self
    {
        return new self(sprintf(
            'Unsupported URL scheme: %s (supported: http, https)',
            $scheme
        ));
    }

    /**
     * Create for a URL without a host
     */
    public static function missingHost(): self
    {
        return new self('URL host is missing or empty');
    }

    /**
     * Create for a URL containing user info (user:password@host)
     */
    public static function userInfoNotAllowed(): self
    {
        return new self('URL must not contain user info (user:password@host)');
    }

    /**
     * Create for a URL containing a fragment
     */
    public static function fragmentNotAllowed(): self
    {
        return new self('URL must not contain a fragment - fragments are not sent to the server and cannot be signed');
    }

    /**
     * Create for malformed percent-encoding in the path or query
     */
    public static function malformedPercentEncoding(): self
    {
        return new self('URL contains malformed percent-encoding ("%" not followed by two hex digits)');
    }

    /**
     * Create for a URL to sign that already carries a reserved parameter
     */
    public static function reservedParameter(string $name): self
    {
        return new self(sprintf(
            'URL already contains the reserved query parameter: %s',
            $name
        ));
    }

    /**
     * Create for a signed URL missing a required parameter
     */
    public static function missingParameter(string $name): self
    {
        return new self(sprintf(
            'Signed URL is missing the required query parameter: %s',
            $name
        ));
    }

    /**
     * Create for a signed URL carrying a reserved parameter more than once
     */
    public static function duplicateParameter(string $name): self
    {
        return new self(sprintf(
            'Signed URL contains a duplicate query parameter: %s',
            $name
        ));
    }

    /**
     * Create for an expiry value that is not a Unix timestamp
     */
    public static function malformedExpiry(string $value): self
    {
        return new self(sprintf(
            'Signed URL expiry is not a Unix timestamp: %s',
            $value
        ));
    }
}
