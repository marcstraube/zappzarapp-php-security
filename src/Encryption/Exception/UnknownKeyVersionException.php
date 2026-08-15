<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Encryption\Exception;

use RuntimeException;

/**
 * Exception thrown when a ciphertext references a key version that is
 * not present in the key ring
 *
 * This is deliberately distinct from DecryptionException: the ciphertext
 * may be perfectly valid, but the key it was encrypted under has been
 * removed from the ring (or was never provisioned). Callers can react by
 * re-provisioning the key instead of treating the data as corrupted.
 */
final class UnknownKeyVersionException extends RuntimeException
{
    /**
     * Create for a key version missing from the ring
     */
    public static function forVersion(int $version): self
    {
        return new self(sprintf(
            'Key version %d is not present in the key ring (removed or never provisioned)',
            $version
        ));
    }
}
