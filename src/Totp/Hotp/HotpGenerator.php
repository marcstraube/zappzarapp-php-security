<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp\Hotp;

use Zappzarapp\Security\Password\Security\ClearsMemory;
use Zappzarapp\Security\Totp\Exception\InvalidTotpConfigException;
use Zappzarapp\Security\Totp\TotpAlgorithm;
use Zappzarapp\Security\Totp\TotpSecret;

/**
 * HMAC-based one-time password generation per RFC 4226
 *
 * Computes HMAC(secret, counter) with the counter as an 8-byte
 * big-endian value, applies dynamic truncation, and reduces the result
 * to the requested number of decimal digits (zero-padded).
 *
 * This is the shared foundation for TOTP (RFC 6238), where the counter
 * is derived from Unix time. Comparing a generated code against user
 * input must use hash_equals() - TotpAuthenticator does this for you.
 */
final readonly class HotpGenerator
{
    use ClearsMemory;

    /**
     * Generate the HOTP code for a counter value
     *
     * @param TotpSecret $secret The shared secret
     * @param int $counter The moving factor (non-negative)
     * @param int $digits Code length, 6 to 8 digits
     * @param TotpAlgorithm $algorithm HMAC hash algorithm
     *
     * @throws InvalidTotpConfigException If the counter is negative or digits are out of range
     */
    public function generate(
        TotpSecret $secret,
        int $counter,
        int $digits = 6,
        TotpAlgorithm $algorithm = TotpAlgorithm::Sha1,
    ): string {
        if ($counter < 0) {
            throw InvalidTotpConfigException::invalidCounter($counter);
        }

        if ($digits < 6 || $digits > 8) {
            throw InvalidTotpConfigException::invalidDigits($digits);
        }

        $secretBytes = $secret->bytes();

        try {
            $mac = hash_hmac($algorithm->hashName(), pack('J', $counter), $secretBytes, true);
        } finally {
            $this->clearMemory($secretBytes);
        }

        $offset = ord($mac[strlen($mac) - 1]) & 0x0F;

        $binaryCode = ((ord($mac[$offset]) & 0x7F) << 24)
            | (ord($mac[$offset + 1]) << 16)
            | (ord($mac[$offset + 2]) << 8)
            | ord($mac[$offset + 3]);

        return str_pad(
            (string) ($binaryCode % (10 ** $digits)),
            $digits,
            '0',
            STR_PAD_LEFT
        );
    }
}
