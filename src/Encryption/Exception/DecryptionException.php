<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption\Exception;

use RuntimeException;

/**
 * Exception thrown when authenticated decryption fails
 *
 * The message deliberately does not distinguish between a wrong key,
 * tampered ciphertext, or mismatched additional data - detailed failure
 * reasons would create a decryption oracle.
 */
final class DecryptionException extends RuntimeException
{
    /**
     * Create for a failed decryption
     */
    public static function failed(): self
    {
        return new self(
            'Decryption failed (wrong key, tampered ciphertext, or mismatched additional data)'
        );
    }
}
