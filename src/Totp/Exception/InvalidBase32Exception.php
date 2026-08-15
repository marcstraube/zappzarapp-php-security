<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when base32 input fails strict decoding
 *
 * The offending input is never echoed back in exception messages - it
 * may be (mistyped) secret material.
 */
final class InvalidBase32Exception extends InvalidArgumentException
{
    /**
     * Create for input containing characters outside the RFC 4648 alphabet
     */
    public static function invalidCharacter(): self
    {
        return new self('Base32 input contains characters outside the RFC 4648 alphabet');
    }

    /**
     * Create for padding that is not at the end or has an impossible length
     */
    public static function invalidPadding(): self
    {
        return new self('Base32 input has invalid padding');
    }

    /**
     * Create for a non-canonical encoding (unused trailing bits are not zero)
     */
    public static function nonCanonical(): self
    {
        return new self('Base32 input is not canonical (unused trailing bits must be zero)');
    }
}
