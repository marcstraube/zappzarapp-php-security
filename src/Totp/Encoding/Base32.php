<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Totp\Encoding;

use SensitiveParameter;
use Zappzarapp\Security\Totp\Exception\InvalidBase32Exception;

/**
 * Strict RFC 4648 base32 codec for TOTP secret provisioning
 *
 * Encoding is unpadded uppercase, the convention used in otpauth:// URIs.
 * Decoding is deliberately strict: it accepts upper- and lowercase and
 * optional trailing padding, but rejects characters outside the alphabet,
 * padding anywhere but the end, impossible input lengths, and
 * non-canonical encodings (unused trailing bits must be zero) - so every
 * byte string has exactly one accepted spelling per padding variant.
 */
final readonly class Base32
{
    /**
     * RFC 4648 base32 alphabet
     */
    public const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Encode bytes as unpadded uppercase base32
     */
    public static function encode(
        #[SensitiveParameter]
        string $bytes,
    ): string {
        $bits    = 0;
        $buffer  = 0;
        $encoded = '';

        foreach (str_split($bytes) as $byte) {
            $buffer = ($buffer << 8) | ord($byte);
            $bits += 8;

            while ($bits >= 5) {
                $bits -= 5;
                $encoded .= self::ALPHABET[($buffer >> $bits) & 0x1F];
            }
        }

        if ($bits > 0) {
            $encoded .= self::ALPHABET[($buffer << (5 - $bits)) & 0x1F];
        }

        return $encoded;
    }

    /**
     * Decode base32 into bytes
     *
     * @throws InvalidBase32Exception If the input is not strict RFC 4648 base32
     */
    public static function decode(
        #[SensitiveParameter]
        string $encoded,
    ): string {
        $unpadded = self::stripPadding($encoded);
        $bits     = 0;
        $buffer   = 0;
        $bytes    = '';

        foreach (str_split(strtoupper($unpadded)) as $character) {
            $value = strpos(self::ALPHABET, $character);

            if ($value === false) {
                throw InvalidBase32Exception::invalidCharacter();
            }

            $buffer = ($buffer << 5) | $value;
            $bits += 5;

            if ($bits >= 8) {
                $bits -= 8;
                $bytes .= chr(($buffer >> $bits) & 0xFF);
            }
        }

        if ($bits >= 5) {
            throw InvalidBase32Exception::invalidPadding();
        }

        if (($buffer & ((1 << $bits) - 1)) !== 0) {
            throw InvalidBase32Exception::nonCanonical();
        }

        return $bytes;
    }

    /**
     * Remove optional trailing padding, enforcing RFC 4648 lengths
     *
     * Padding must be absent entirely or exactly fill the final 8-character
     * block - anything else (padding elsewhere, wrong amount, padding-only
     * input) is rejected.
     *
     * @throws InvalidBase32Exception If the padding is misplaced or has the wrong length
     */
    private static function stripPadding(string $encoded): string
    {
        $unpadded = rtrim($encoded, '=');

        if (str_contains($unpadded, '=')) {
            throw InvalidBase32Exception::invalidPadding();
        }

        $padding = strlen($encoded) - strlen($unpadded);

        if ($padding !== 0 && $padding !== (8 - strlen($unpadded) % 8) % 8) {
            throw InvalidBase32Exception::invalidPadding();
        }

        return $unpadded;
    }
}
