<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp\Recovery;

use Random\RandomException;
use Zappzarapp\Security\Totp\Exception\InvalidRecoveryCodeException;

/**
 * Cryptographically random recovery code generation
 *
 * Codes have four groups of four characters (xxxx-xxxx-xxxx-xxxx) from
 * an alphabet without look-alike characters (no i, l, o, 0, 1), giving
 * ~79 bit of entropy per code - far beyond online-guessing reach even
 * without rate limiting.
 *
 * ## Usage
 *
 * ```php
 * $generator = new RecoveryCodeGenerator();
 * $verifier  = new RecoveryCodeVerifier();
 *
 * $codes  = $generator->generate();                          // show once
 * $hashes = array_map($verifier->hash(...), $codes);         // persist
 * ```
 */
final readonly class RecoveryCodeGenerator
{
    /**
     * Code alphabet without look-alike characters
     */
    public const string ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

    /**
     * Number of character groups per code
     */
    private const int GROUPS = 4;

    /**
     * Characters per group
     */
    private const int GROUP_LENGTH = 4;

    /**
     * Generate a fresh set of recovery codes
     *
     * @param int $count Number of codes (1 to 100)
     *
     * @return list<RecoveryCode>
     *
     * @throws InvalidRecoveryCodeException If the count is out of range
     * @throws RandomException If no secure randomness source is available
     */
    public function generate(int $count = 10): array
    {
        if ($count < 1 || $count > 100) {
            throw InvalidRecoveryCodeException::invalidCount($count);
        }

        $codes = [];

        for ($index = 0; $index < $count; $index++) {
            $codes[] = new RecoveryCode($this->generateCode());
        }

        return $codes;
    }

    /**
     * Generate one code as dash-separated character groups
     *
     * @throws RandomException If no secure randomness source is available
     */
    private function generateCode(): string
    {
        $groups = [];

        for ($group = 0; $group < self::GROUPS; $group++) {
            $characters = '';

            for ($position = 0; $position < self::GROUP_LENGTH; $position++) {
                $characters .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
            }

            $groups[] = $characters;
        }

        return implode('-', $groups);
    }
}
