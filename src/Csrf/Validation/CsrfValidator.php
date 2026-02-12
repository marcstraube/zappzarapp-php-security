<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Validation;

use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Storage\CsrfStorageInterface;
use Zappzarapp\Security\Csrf\Token\CsrfToken;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;

/**
 * CSRF token validator
 *
 * Validates tokens against stored values using timing-safe comparison.
 */
final readonly class CsrfValidator
{
    private const string DEFAULT_STORAGE_KEY = '_csrf';

    public function __construct(
        private CsrfStorageInterface $storage,
        private string $storageKey = self::DEFAULT_STORAGE_KEY,
        private ?SecurityLoggerInterface $logger = null,
    ) {
    }

    /**
     * Validate a token against the stored value
     *
     * @param string $submittedToken The token from the request
     * @param bool $consume Remove token after successful validation (single-use)
     *
     * @throws CsrfTokenMismatchException If validation fails
     * @throws InvalidCsrfTokenException If token format is invalid
     */
    public function validate(string $submittedToken, bool $consume = false): void
    {
        if ($submittedToken === '') {
            $this->logValidationFailure('missing_token', 'No token submitted');
            throw CsrfTokenMismatchException::missingToken();
        }

        // Validate format (may throw InvalidCsrfTokenException)
        $token = new CsrfToken($submittedToken);

        // Get stored token
        $storedValue = $this->storage->retrieve($this->storageKey);

        if ($storedValue === null) {
            $this->logValidationFailure('no_stored_token', 'No token in storage');
            throw CsrfTokenMismatchException::noStoredToken();
        }

        // Timing-safe comparison
        if (!hash_equals($storedValue, $token->value())) {
            $this->logValidationFailure('token_mismatch', 'Token does not match');
            throw CsrfTokenMismatchException::tokenMismatch();
        }

        // Consume token if single-use
        if ($consume) {
            $this->storage->remove($this->storageKey);
        }
    }

    /**
     * Log a CSRF validation failure
     */
    private function logValidationFailure(string $reason, string $message): void
    {
        $this->logger?->warning('CSRF validation failed: ' . $message, [
            'reason'      => $reason,
            'storage_key' => $this->storageKey,
        ]);
    }

    /**
     * Check if a token is valid without throwing
     *
     * @param string $submittedToken The token from the request
     */
    public function isValid(string $submittedToken): bool
    {
        try {
            $this->validate($submittedToken);

            return true;
        } catch (CsrfTokenMismatchException|InvalidCsrfTokenException) {
            return false;
        }
    }

    /**
     * Store a token for later validation
     *
     * @param CsrfToken $token The token to store
     * @param int|null $ttl Time-to-live in seconds
     */
    public function storeToken(CsrfToken $token, ?int $ttl = null): void
    {
        $this->storage->store($this->storageKey, $token->value(), $ttl);
    }

    /**
     * Get the currently stored token
     */
    public function getStoredToken(): ?string
    {
        return $this->storage->retrieve($this->storageKey);
    }

    /**
     * Clear the stored token
     */
    public function clearToken(): void
    {
        $this->storage->remove($this->storageKey);
    }
}
