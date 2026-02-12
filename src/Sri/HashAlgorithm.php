<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Sri;

/**
 * SRI hash algorithms
 *
 * Only SHA-384 and SHA-512 are supported. SHA-256 is intentionally
 * not included as SHA-384 provides better security with minimal
 * performance overhead and is the recommended algorithm for SRI.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
 */
enum HashAlgorithm: string
{
    case SHA384 = 'sha384';
    case SHA512 = 'sha512';

    /**
     * Get the algorithm prefix for SRI
     */
    public function prefix(): string
    {
        return $this->value;
    }

    /**
     * Get the expected hash length in bytes
     */
    public function byteLength(): int
    {
        return match ($this) {
            self::SHA384 => 48,
            self::SHA512 => 64,
        };
    }

    /**
     * Get the expected base64 length
     */
    public function base64Length(): int
    {
        return (int) ceil($this->byteLength() * 4 / 3);
    }

    /**
     * Get the recommended algorithm
     *
     * SHA-384 provides the best balance of security and performance.
     */
    public static function recommended(): self
    {
        return self::SHA384;
    }

    /**
     * Create from string (case-insensitive)
     */
    public static function fromString(string $algorithm): ?self
    {
        return match (strtolower($algorithm)) {
            'sha384', 'sha-384' => self::SHA384,
            'sha512', 'sha-512' => self::SHA512,
            default => null,
        };
    }
}
