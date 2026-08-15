<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Totp\Recovery;

use SensitiveParameter;
use Zappzarapp\Security\Password\Hashing\DefaultPasswordHasher;
use Zappzarapp\Security\Password\Hashing\PasswordHasher;

/**
 * Recovery code hashing and one-time verification
 *
 * Codes are hashed like passwords (Argon2id by default) - a database
 * leak must not expose usable recovery codes. Verification returns the
 * index of the matching hash so the caller can delete exactly that hash,
 * which is what makes each code single-use:
 *
 * ## Usage
 *
 * ```php
 * $verifier = new RecoveryCodeVerifier();
 *
 * $index = $verifier->verify($submittedCode, $user->recoveryCodeHashes);
 *
 * if ($index !== null) {
 *     unset($user->recoveryCodeHashes[$index]); // consume - single use
 * }
 * ```
 */
final readonly class RecoveryCodeVerifier
{
    public function __construct(
        private PasswordHasher $hasher = new DefaultPasswordHasher(),
    ) {
    }

    /**
     * Hash a recovery code for storage
     */
    public function hash(RecoveryCode $code): string
    {
        return $this->hasher->hash($code->normalized());
    }

    /**
     * Verify user input against the stored hashes
     *
     * Input is canonicalized first (case and separators are ignored).
     * Returns the array index of the matching hash - delete that hash to
     * consume the code - or null if no hash matches.
     *
     * @param string $input The user-submitted code
     * @param array<int, string> $hashes The stored recovery code hashes
     */
    public function verify(
        #[SensitiveParameter]
        string $input,
        array $hashes,
    ): ?int {
        $normalized = RecoveryCode::normalize($input);

        if ($normalized === '') {
            return null;
        }

        return array_find_key(
            $hashes,
            fn (string $hash): bool => $this->hasher->verify($normalized, $hash)
        );
    }
}
