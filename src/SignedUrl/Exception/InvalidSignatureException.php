<?php

declare(strict_types=1);

namespace Zappzarapp\Security\SignedUrl\Exception;

use RuntimeException;

/**
 * Exception thrown when a signed URL carries a signature that does not
 * match its contents
 *
 * The message is deliberately generic - it reveals nothing about which
 * component of the URL failed to match.
 */
final class InvalidSignatureException extends RuntimeException
{
    /**
     * Create for a signature mismatch
     */
    public static function mismatch(): self
    {
        return new self('Signed URL signature does not match the URL contents');
    }
}
