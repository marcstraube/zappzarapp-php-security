<?php

declare(strict_types=1);

namespace Zappzarapp\Security\SignedUrl\Exception;

use RuntimeException;

/**
 * Exception thrown when a signed URL has a valid signature but its expiry
 * timestamp has passed
 */
final class UrlExpiredException extends RuntimeException
{
    /**
     * Create for an expiry timestamp in the past
     */
    public static function expiredAt(int $expiresAt, int $now): self
    {
        return new self(sprintf(
            'Signed URL expired at %d (now: %d)',
            $expiresAt,
            $now
        ));
    }
}
