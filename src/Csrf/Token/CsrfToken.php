<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Token;

use Override;
use Stringable;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;

/**
 * Immutable CSRF token value object
 *
 * Represents a validated CSRF token.
 */
final readonly class CsrfToken implements Stringable
{
    /**
     * Minimum token length in bytes (before base64 encoding)
     */
    public const int MIN_BYTES = 32;

    /**
     * @param string $value The base64-encoded token value
     *
     * @throws InvalidCsrfTokenException If token is invalid
     */
    public function __construct(
        private string $value,
    ) {
        $this->validate();
    }

    /**
     * Get the token value
     */
    public function value(): string
    {
        return $this->value;
    }

    /**
     * Get the raw (decoded) bytes
     */
    public function rawBytes(): string
    {
        /** @var string $decoded Already validated in constructor */
        $decoded = base64_decode($this->value, true);

        return $decoded;
    }

    #[Override]
    public function __toString(): string
    {
        return $this->value;
    }

    /**
     * Compare tokens in constant time
     */
    public function equals(self $other): bool
    {
        return hash_equals($this->value, $other->value);
    }

    /**
     * Compare with raw string in constant time
     */
    public function equalsString(string $token): bool
    {
        return hash_equals($this->value, $token);
    }

    /**
     * Validate token format
     *
     * @throws InvalidCsrfTokenException If token is invalid
     */
    private function validate(): void
    {
        if ($this->value === '') {
            throw InvalidCsrfTokenException::emptyToken();
        }

        // Check for injection characters
        if (str_contains($this->value, ';') || str_contains($this->value, "\r") || str_contains($this->value, "\n")) {
            throw InvalidCsrfTokenException::invalidFormat($this->value, 'contains control characters');
        }

        // Validate base64
        $decoded = base64_decode($this->value, true);
        if ($decoded === false) {
            throw InvalidCsrfTokenException::invalidBase64($this->value);
        }

        // Check minimum entropy
        if (strlen($decoded) < self::MIN_BYTES) {
            throw InvalidCsrfTokenException::insufficientEntropy(self::MIN_BYTES, strlen($decoded));
        }
    }
}
