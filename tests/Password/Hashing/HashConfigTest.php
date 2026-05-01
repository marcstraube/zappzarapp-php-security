<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Hashing;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Hashing\HashAlgorithm;
use Zappzarapp\Security\Password\Hashing\HashConfig;

#[CoversClass(HashConfig::class)]
final class HashConfigTest extends TestCase
{
    #[Test]
    public function testDefaultConstructorValues(): void
    {
        $config = new HashConfig();

        $this->assertSame(HashAlgorithm::ARGON2ID, $config->algorithm);
        $this->assertSame(HashConfig::DEFAULT_ARGON2_MEMORY, $config->memoryCost);
        $this->assertSame(HashConfig::DEFAULT_ARGON2_TIME, $config->timeCost);
        $this->assertSame(HashConfig::DEFAULT_ARGON2_THREADS, $config->threads);
        $this->assertSame(HashConfig::DEFAULT_BCRYPT_COST, $config->bcryptCost);
    }

    #[Test]
    public function testCustomConstructorValues(): void
    {
        $config = new HashConfig(
            algorithm: HashAlgorithm::BCRYPT,
            memoryCost: 131072,
            timeCost: 8,
            threads: 4,
            bcryptCost: 14
        );

        $this->assertSame(HashAlgorithm::BCRYPT, $config->algorithm);
        $this->assertSame(131072, $config->memoryCost);
        $this->assertSame(8, $config->timeCost);
        $this->assertSame(4, $config->threads);
        $this->assertSame(14, $config->bcryptCost);
    }

    #[Test]
    public function testToOptionsForArgon2id(): void
    {
        $config  = new HashConfig(HashAlgorithm::ARGON2ID, 65536, 4, 2);
        $options = $config->toOptions();

        $this->assertSame([
            'memory_cost' => 65536,
            'time_cost'   => 4,
            'threads'     => 2,
        ], $options);
    }

    #[Test]
    public function testToOptionsForArgon2i(): void
    {
        $config  = new HashConfig(HashAlgorithm::ARGON2I, 65536, 4, 2);
        $options = $config->toOptions();

        $this->assertSame([
            'memory_cost' => 65536,
            'time_cost'   => 4,
            'threads'     => 2,
        ], $options);
    }

    #[Test]
    public function testToOptionsForBcrypt(): void
    {
        $config  = new HashConfig(HashAlgorithm::BCRYPT, bcryptCost: 12);
        $options = $config->toOptions();

        $this->assertSame([
            'cost' => 12,
        ], $options);
    }

    #[Test]
    public function testWithAlgorithmReturnsNewInstance(): void
    {
        $original = new HashConfig(HashAlgorithm::ARGON2ID);
        $modified = $original->withAlgorithm(HashAlgorithm::BCRYPT);

        $this->assertNotSame($original, $modified);
        $this->assertSame(HashAlgorithm::ARGON2ID, $original->algorithm);
        $this->assertSame(HashAlgorithm::BCRYPT, $modified->algorithm);
    }

    #[Test]
    public function testWithAlgorithmPreservesOtherValues(): void
    {
        $original = new HashConfig(HashAlgorithm::ARGON2ID, 131072, 8, 4, 14);
        $modified = $original->withAlgorithm(HashAlgorithm::BCRYPT);

        $this->assertSame(131072, $modified->memoryCost);
        $this->assertSame(8, $modified->timeCost);
        $this->assertSame(4, $modified->threads);
        $this->assertSame(14, $modified->bcryptCost);
    }

    #[Test]
    public function testWithMemoryCostReturnsNewInstance(): void
    {
        $original = new HashConfig();
        $modified = $original->withMemoryCost(131072);

        $this->assertNotSame($original, $modified);
        $this->assertSame(HashConfig::DEFAULT_ARGON2_MEMORY, $original->memoryCost);
        $this->assertSame(131072, $modified->memoryCost);
    }

    #[Test]
    public function testWithMemoryCostPreservesOtherValues(): void
    {
        $original = new HashConfig(HashAlgorithm::ARGON2I, 65536, 8, 4, 14);
        $modified = $original->withMemoryCost(131072);

        $this->assertSame(HashAlgorithm::ARGON2I, $modified->algorithm);
        $this->assertSame(8, $modified->timeCost);
        $this->assertSame(4, $modified->threads);
        $this->assertSame(14, $modified->bcryptCost);
    }

    #[Test]
    public function testWithTimeCostReturnsNewInstance(): void
    {
        $original = new HashConfig();
        $modified = $original->withTimeCost(8);

        $this->assertNotSame($original, $modified);
        $this->assertSame(HashConfig::DEFAULT_ARGON2_TIME, $original->timeCost);
        $this->assertSame(8, $modified->timeCost);
    }

    #[Test]
    public function testWithTimeCostPreservesOtherValues(): void
    {
        $original = new HashConfig(HashAlgorithm::ARGON2I, 131072, 4, 4, 14);
        $modified = $original->withTimeCost(8);

        $this->assertSame(HashAlgorithm::ARGON2I, $modified->algorithm);
        $this->assertSame(131072, $modified->memoryCost);
        $this->assertSame(4, $modified->threads);
        $this->assertSame(14, $modified->bcryptCost);
    }

    #[Test]
    public function testWithBcryptCostReturnsNewInstance(): void
    {
        $original = new HashConfig();
        $modified = $original->withBcryptCost(14);

        $this->assertNotSame($original, $modified);
        $this->assertSame(HashConfig::DEFAULT_BCRYPT_COST, $original->bcryptCost);
        $this->assertSame(14, $modified->bcryptCost);
    }

    #[Test]
    public function testWithBcryptCostPreservesOtherValues(): void
    {
        $original = new HashConfig(HashAlgorithm::BCRYPT, 131072, 8, 4, 12);
        $modified = $original->withBcryptCost(14);

        $this->assertSame(HashAlgorithm::BCRYPT, $modified->algorithm);
        $this->assertSame(131072, $modified->memoryCost);
        $this->assertSame(8, $modified->timeCost);
        $this->assertSame(4, $modified->threads);
    }

    #[Test]
    public function testArgon2idStaticFactory(): void
    {
        $config = HashConfig::argon2id();

        $this->assertSame(HashAlgorithm::ARGON2ID, $config->algorithm);
        $this->assertSame(HashConfig::DEFAULT_ARGON2_MEMORY, $config->memoryCost);
        $this->assertSame(HashConfig::DEFAULT_ARGON2_TIME, $config->timeCost);
        $this->assertSame(HashConfig::DEFAULT_ARGON2_THREADS, $config->threads);
    }

    #[Test]
    public function testBcryptStaticFactoryWithDefaultCost(): void
    {
        $config = HashConfig::bcrypt();

        $this->assertSame(HashAlgorithm::BCRYPT, $config->algorithm);
        $this->assertSame(HashConfig::DEFAULT_BCRYPT_COST, $config->bcryptCost);
    }

    #[Test]
    public function testBcryptStaticFactoryWithCustomCost(): void
    {
        $config = HashConfig::bcrypt(14);

        $this->assertSame(HashAlgorithm::BCRYPT, $config->algorithm);
        $this->assertSame(14, $config->bcryptCost);
    }

    #[Test]
    public function testHighSecurityStaticFactory(): void
    {
        $config = HashConfig::highSecurity();

        $this->assertSame(HashAlgorithm::ARGON2ID, $config->algorithm);
        $this->assertSame(131072, $config->memoryCost);
        $this->assertSame(6, $config->timeCost);
        $this->assertSame(2, $config->threads);
    }

    #[Test]
    public function testDefaultConstants(): void
    {
        $this->assertSame(65536, HashConfig::DEFAULT_ARGON2_MEMORY);
        $this->assertSame(4, HashConfig::DEFAULT_ARGON2_TIME);
        $this->assertSame(1, HashConfig::DEFAULT_ARGON2_THREADS);
        $this->assertSame(12, HashConfig::DEFAULT_BCRYPT_COST);
    }

    #[Test]
    public function testChainedWithMethods(): void
    {
        $config = (new HashConfig())
            ->withAlgorithm(HashAlgorithm::ARGON2I)
            ->withMemoryCost(262144)
            ->withTimeCost(10)
            ->withBcryptCost(15);

        $this->assertSame(HashAlgorithm::ARGON2I, $config->algorithm);
        $this->assertSame(262144, $config->memoryCost);
        $this->assertSame(10, $config->timeCost);
        $this->assertSame(15, $config->bcryptCost);
    }

    #[Test]
    public function testImmutabilityOnChainedCalls(): void
    {
        $original = new HashConfig();
        $step1    = $original->withAlgorithm(HashAlgorithm::BCRYPT);
        $step2    = $step1->withBcryptCost(14);

        $this->assertSame(HashAlgorithm::ARGON2ID, $original->algorithm);
        $this->assertSame(HashAlgorithm::BCRYPT, $step1->algorithm);
        $this->assertSame(HashConfig::DEFAULT_BCRYPT_COST, $step1->bcryptCost);
        $this->assertSame(14, $step2->bcryptCost);
    }
}
