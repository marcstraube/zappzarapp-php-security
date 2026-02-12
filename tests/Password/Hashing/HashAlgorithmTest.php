<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Hashing;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Hashing\HashAlgorithm;

#[CoversClass(HashAlgorithm::class)]
final class HashAlgorithmTest extends TestCase
{
    public function testAllCasesExist(): void
    {
        $cases = HashAlgorithm::cases();

        $this->assertCount(3, $cases);
        $this->assertContains(HashAlgorithm::ARGON2ID, $cases);
        $this->assertContains(HashAlgorithm::ARGON2I, $cases);
        $this->assertContains(HashAlgorithm::BCRYPT, $cases);
    }

    public function testArgon2idValue(): void
    {
        $this->assertSame('argon2id', HashAlgorithm::ARGON2ID->value);
    }

    public function testArgon2iValue(): void
    {
        $this->assertSame('argon2i', HashAlgorithm::ARGON2I->value);
    }

    public function testBcryptValue(): void
    {
        $this->assertSame('bcrypt', HashAlgorithm::BCRYPT->value);
    }

    public function testArgon2idConstant(): void
    {
        $this->assertSame(PASSWORD_ARGON2ID, HashAlgorithm::ARGON2ID->constant());
    }

    public function testArgon2iConstant(): void
    {
        $this->assertSame(PASSWORD_ARGON2I, HashAlgorithm::ARGON2I->constant());
    }

    public function testBcryptConstant(): void
    {
        $this->assertSame(PASSWORD_BCRYPT, HashAlgorithm::BCRYPT->constant());
    }

    public function testArgon2idHasNoLengthLimit(): void
    {
        $this->assertFalse(HashAlgorithm::ARGON2ID->hasLengthLimit());
    }

    public function testArgon2iHasNoLengthLimit(): void
    {
        $this->assertFalse(HashAlgorithm::ARGON2I->hasLengthLimit());
    }

    public function testBcryptHasLengthLimit(): void
    {
        $this->assertTrue(HashAlgorithm::BCRYPT->hasLengthLimit());
    }

    public function testArgon2idMaxLengthIsZero(): void
    {
        $this->assertSame(0, HashAlgorithm::ARGON2ID->maxLength());
    }

    public function testArgon2iMaxLengthIsZero(): void
    {
        $this->assertSame(0, HashAlgorithm::ARGON2I->maxLength());
    }

    public function testBcryptMaxLengthIs72(): void
    {
        $this->assertSame(72, HashAlgorithm::BCRYPT->maxLength());
    }

    public function testCanCreateFromString(): void
    {
        $argon2id = HashAlgorithm::from('argon2id');
        $argon2i  = HashAlgorithm::from('argon2i');
        $bcrypt   = HashAlgorithm::from('bcrypt');

        $this->assertSame(HashAlgorithm::ARGON2ID, $argon2id);
        $this->assertSame(HashAlgorithm::ARGON2I, $argon2i);
        $this->assertSame(HashAlgorithm::BCRYPT, $bcrypt);
    }

    public function testTryFromWithInvalidValue(): void
    {
        $result = HashAlgorithm::tryFrom('invalid');

        $this->assertNull($result);
    }

    public function testTryFromWithValidValue(): void
    {
        $result = HashAlgorithm::tryFrom('argon2id');

        $this->assertSame(HashAlgorithm::ARGON2ID, $result);
    }
}
