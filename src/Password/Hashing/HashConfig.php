<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Hashing;

/**
 * Password hash configuration
 */
final readonly class HashConfig
{
    /**
     * Default Argon2 memory cost (64 MB)
     */
    public const int DEFAULT_ARGON2_MEMORY = 65536;

    /**
     * Default Argon2 time cost
     */
    public const int DEFAULT_ARGON2_TIME = 4;

    /**
     * Default Argon2 threads
     */
    public const int DEFAULT_ARGON2_THREADS = 1;

    /**
     * Default bcrypt cost
     */
    public const int DEFAULT_BCRYPT_COST = 12;

    public function __construct(
        public HashAlgorithm $algorithm = HashAlgorithm::ARGON2ID,
        public int $memoryCost = self::DEFAULT_ARGON2_MEMORY,
        public int $timeCost = self::DEFAULT_ARGON2_TIME,
        public int $threads = self::DEFAULT_ARGON2_THREADS,
        public int $bcryptCost = self::DEFAULT_BCRYPT_COST,
    ) {
    }

    /**
     * Get options array for password_hash()
     *
     * @return array<string, int>
     */
    public function toOptions(): array
    {
        return match ($this->algorithm) {
            HashAlgorithm::ARGON2ID, HashAlgorithm::ARGON2I => [
                'memory_cost' => $this->memoryCost,
                'time_cost'   => $this->timeCost,
                'threads'     => $this->threads,
            ],
            HashAlgorithm::BCRYPT => [
                'cost' => $this->bcryptCost,
            ],
        };
    }

    /**
     * Create with custom algorithm
     */
    public function withAlgorithm(HashAlgorithm $algorithm): self
    {
        return new self(
            $algorithm,
            $this->memoryCost,
            $this->timeCost,
            $this->threads,
            $this->bcryptCost
        );
    }

    /**
     * Create with custom memory cost (Argon2)
     */
    public function withMemoryCost(int $memoryCost): self
    {
        return new self(
            $this->algorithm,
            $memoryCost,
            $this->timeCost,
            $this->threads,
            $this->bcryptCost
        );
    }

    /**
     * Create with custom time cost (Argon2)
     */
    public function withTimeCost(int $timeCost): self
    {
        return new self(
            $this->algorithm,
            $this->memoryCost,
            $timeCost,
            $this->threads,
            $this->bcryptCost
        );
    }

    /**
     * Create with custom bcrypt cost
     */
    public function withBcryptCost(int $cost): self
    {
        return new self(
            $this->algorithm,
            $this->memoryCost,
            $this->timeCost,
            $this->threads,
            $cost
        );
    }

    /**
     * Create default Argon2id configuration
     */
    public static function argon2id(): self
    {
        return new self(HashAlgorithm::ARGON2ID);
    }

    /**
     * Create bcrypt configuration
     */
    public static function bcrypt(int $cost = self::DEFAULT_BCRYPT_COST): self
    {
        return new self(
            algorithm: HashAlgorithm::BCRYPT,
            bcryptCost: $cost
        );
    }

    /**
     * Create high-security configuration (slower)
     */
    public static function highSecurity(): self
    {
        return new self(
            algorithm: HashAlgorithm::ARGON2ID,
            memoryCost: 131072, // 128 MB
            timeCost: 6,
            threads: 2
        );
    }
}
