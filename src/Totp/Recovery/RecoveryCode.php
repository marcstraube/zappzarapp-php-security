<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Totp\Recovery;

use SensitiveParameter;
use Zappzarapp\Security\Secrets\SecretValue;

/**
 * Single-use recovery code in plain text
 *
 * Exists only during enrollment: show it to the user once, store only
 * the hash (RecoveryCodeVerifier::hash()), then let this object go out
 * of scope. The plain text is wrapped in a SecretValue - redacted debug
 * output, redacted JSON serialization, serialize() protection, and
 * sodium_memzero() on destruction.
 */
final readonly class RecoveryCode
{
    private SecretValue $plainText;

    public function __construct(
        #[SensitiveParameter]
        string $plainText,
    ) {
        $this->plainText = new SecretValue($plainText);
    }

    /**
     * Get the plain text for one-time display to the user
     */
    public function reveal(): string
    {
        return $this->plainText->reveal();
    }

    /**
     * Get the canonical form used for hashing and verification
     *
     * Lowercased with all separators stripped, so user input with or
     * without dashes and in any case verifies against the same hash.
     */
    public function normalized(): string
    {
        return self::normalize($this->plainText->reveal());
    }

    /**
     * Canonicalize a (user-supplied) code: lowercase, alphanumerics only
     */
    public static function normalize(
        #[SensitiveParameter]
        string $input,
    ): string {
        return (string) preg_replace('/[^a-z0-9]+/', '', strtolower($input));
    }

    /**
     * Redact the code in var_dump() and debugger output
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['plainText' => '***REDACTED***'];
    }
}
