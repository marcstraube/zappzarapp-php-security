<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp;

/**
 * HMAC hash algorithm for HOTP/TOTP code generation
 *
 * SHA-1 is the RFC 6238 default and the only algorithm universally
 * supported by authenticator apps. Its known collision weaknesses do not
 * affect HMAC-based OTP security. SHA-256/SHA-512 are available as
 * explicit opt-in for controlled client environments.
 */
enum TotpAlgorithm: string
{
    case Sha1   = 'SHA1';
    case Sha256 = 'SHA256';
    case Sha512 = 'SHA512';

    /**
     * Get the hash name expected by hash_hmac()
     */
    public function hashName(): string
    {
        return match ($this) {
            self::Sha1   => 'sha1',
            self::Sha256 => 'sha256',
            self::Sha512 => 'sha512',
        };
    }

    /**
     * Get the recommended secret length: the hash output size (RFC 6238)
     *
     * @return positive-int
     */
    public function recommendedSecretBytes(): int
    {
        return match ($this) {
            self::Sha1   => 20,
            self::Sha256 => 32,
            self::Sha512 => 64,
        };
    }
}
