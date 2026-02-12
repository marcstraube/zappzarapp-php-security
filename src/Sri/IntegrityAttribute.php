<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Sri;

use Override;
use Stringable;
use Zappzarapp\Security\Sri\Exception\InvalidHashException;

/**
 * SRI integrity attribute value object
 *
 * Represents one or more SRI hashes for the integrity attribute.
 */
final readonly class IntegrityAttribute implements Stringable
{
    /**
     * @param list<array{algorithm: HashAlgorithm, hash: string}> $hashes List of algorithm/hash pairs
     */
    public function __construct(
        private array $hashes,
    ) {
        if ($this->hashes === []) {
            throw new InvalidHashException('IntegrityAttribute requires at least one hash');
        }

        foreach ($this->hashes as $hash) {
            $this->validateHash($hash['algorithm'], $hash['hash']);
        }
    }

    /**
     * Create from a single hash
     */
    public static function fromHash(HashAlgorithm $algorithm, string $hash): self
    {
        return new self([['algorithm' => $algorithm, 'hash' => $hash]]);
    }

    /**
     * Create from content
     */
    public static function fromContent(string $content, HashAlgorithm $algorithm = HashAlgorithm::SHA384): self
    {
        $hash = base64_encode(hash($algorithm->value, $content, true));

        return self::fromHash($algorithm, $hash);
    }

    /**
     * Create from an integrity string
     *
     * @throws InvalidHashException If string is invalid
     */
    public static function fromString(string $integrity): self
    {
        $hashes = [];
        $parts  = preg_split('/\s+/', trim($integrity));

        if ($parts === false) {
            throw InvalidHashException::invalidFormat($integrity);
        }

        foreach ($parts as $part) {
            if ($part === '') {
                continue;
            }

            $matches = [];
            if (preg_match('/^(sha384|sha512)-(.+)$/i', $part, $matches) !== 1) {
                throw InvalidHashException::invalidFormat($part);
            }

            $algorithm = HashAlgorithm::fromString($matches[1]);
            if (!$algorithm instanceof HashAlgorithm) {
                throw InvalidHashException::unsupportedAlgorithm($matches[1]);
            }

            $hashes[] = ['algorithm' => $algorithm, 'hash' => $matches[2]];
        }

        return new self($hashes);
    }

    /**
     * Add an additional hash (for algorithm migration)
     */
    public function withHash(HashAlgorithm $algorithm, string $hash): self
    {
        return new self([...$this->hashes, ['algorithm' => $algorithm, 'hash' => $hash]]);
    }

    /**
     * Get all hashes
     *
     * @return list<array{algorithm: HashAlgorithm, hash: string}>
     */
    public function hashes(): array
    {
        return $this->hashes;
    }

    /**
     * Get the primary hash (first one)
     *
     * @return array{algorithm: HashAlgorithm, hash: string}
     */
    public function primaryHash(): array
    {
        return $this->hashes[0];
    }

    /**
     * Verify content against any of the hashes
     */
    public function verify(string $content): bool
    {
        foreach ($this->hashes as $hashData) {
            $expected = $hashData['hash'];
            $actual   = base64_encode(hash($hashData['algorithm']->value, $content, true));

            // Constant-time comparison
            if (hash_equals($expected, $actual)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build the integrity attribute value
     */
    public function value(): string
    {
        $parts = [];
        foreach ($this->hashes as $hash) {
            $parts[] = $hash['algorithm']->prefix() . '-' . $hash['hash'];
        }

        return implode(' ', $parts);
    }

    #[Override]
    public function __toString(): string
    {
        return $this->value();
    }

    /**
     * Validate a hash value
     *
     * @throws InvalidHashException If hash is invalid
     */
    private function validateHash(HashAlgorithm $algorithm, string $hash): void
    {
        // Validate base64
        $decoded = base64_decode($hash, true);
        if ($decoded === false) {
            throw InvalidHashException::invalidBase64($hash);
        }

        // Validate length
        if (strlen($decoded) !== $algorithm->byteLength()) {
            throw InvalidHashException::invalidFormat(
                $algorithm->prefix() . '-' . $hash
            );
        }
    }
}
