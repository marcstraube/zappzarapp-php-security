<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Nonce;

use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;

/**
 * Validates nonce values for CSP injection attacks
 *
 * Shared validation logic for NonceGenerator and NonceRegistry.
 */
trait ValidatesNonce
{
    /**
     * Validate nonce value for CSP injection attacks
     *
     * @throws InvalidDirectiveValueException If nonce contains invalid characters
     */
    private static function validateNonceValue(string $nonce): void
    {
        // Reject empty nonce
        if ($nonce === '') {
            throw InvalidDirectiveValueException::invalidNonce($nonce, 'cannot be empty');
        }

        // Reject semicolons (CSP directive separator)
        if (str_contains($nonce, ';')) {
            throw InvalidDirectiveValueException::invalidNonce($nonce, 'contains semicolon');
        }

        // Reject control characters (HTTP header injection)
        if (preg_match('/[\x00-\x1F]/', $nonce) === 1) {
            throw InvalidDirectiveValueException::invalidNonce($nonce, 'contains control character');
        }

        // Reject single quotes (CSP value delimiter - nonce is wrapped in 'nonce-...')
        if (str_contains($nonce, "'")) {
            throw InvalidDirectiveValueException::invalidNonce($nonce, 'contains single quote');
        }

        // Reject spaces (CSP value separator - prevents 'nonce-abc unsafe-inline' injection)
        if (str_contains($nonce, ' ')) {
            throw InvalidDirectiveValueException::invalidNonce($nonce, 'contains space');
        }
    }
}
