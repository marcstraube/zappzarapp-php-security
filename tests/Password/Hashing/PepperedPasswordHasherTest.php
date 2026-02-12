<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Hashing;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionException;
use ReflectionMethod;
use Zappzarapp\Security\Password\Hashing\DefaultPasswordHasher;
use Zappzarapp\Security\Password\Hashing\PepperedPasswordHasher;

#[CoversClass(PepperedPasswordHasher::class)]
final class PepperedPasswordHasherTest extends TestCase
{
    private const string TEST_PEPPER = 'test-pepper-32-bytes-long-value!';

    private const string TEST_PASSWORD = 'MySecureP@ssword123';

    private PepperedPasswordHasher $hasher;

    protected function setUp(): void
    {
        $this->hasher = new PepperedPasswordHasher(self::TEST_PEPPER);
    }

    public function testHashProducesValidHash(): void
    {
        $hash = $this->hasher->hash(self::TEST_PASSWORD);

        $this->assertNotEmpty($hash);
        $this->assertNotSame(self::TEST_PASSWORD, $hash);
    }

    public function testVerifyWithCorrectPassword(): void
    {
        $hash = $this->hasher->hash(self::TEST_PASSWORD);

        $this->assertTrue($this->hasher->verify(self::TEST_PASSWORD, $hash));
    }

    public function testVerifyWithIncorrectPassword(): void
    {
        $hash = $this->hasher->hash(self::TEST_PASSWORD);

        $this->assertFalse($this->hasher->verify('WrongPassword', $hash));
    }

    public function testVerifyFailsWithWrongPepper(): void
    {
        $hash = $this->hasher->hash(self::TEST_PASSWORD);

        $otherHasher = new PepperedPasswordHasher('different-pepper-value-here!!!!!');

        $this->assertFalse($otherHasher->verify(self::TEST_PASSWORD, $hash));
    }

    public function testSamePasswordDifferentPeppersProduceDifferentHashes(): void
    {
        $hasher1 = new PepperedPasswordHasher('pepper-one-123456789012345678901');
        $hasher2 = new PepperedPasswordHasher('pepper-two-123456789012345678901');

        $hash1 = $hasher1->hash(self::TEST_PASSWORD);
        $hash2 = $hasher2->hash(self::TEST_PASSWORD);

        // Hashes should be different
        $this->assertNotSame($hash1, $hash2);

        // Each hasher can only verify its own hashes
        $this->assertTrue($hasher1->verify(self::TEST_PASSWORD, $hash1));
        $this->assertFalse($hasher1->verify(self::TEST_PASSWORD, $hash2));
        $this->assertFalse($hasher2->verify(self::TEST_PASSWORD, $hash1));
        $this->assertTrue($hasher2->verify(self::TEST_PASSWORD, $hash2));
    }

    public function testNeedsRehashDelegates(): void
    {
        $hash = $this->hasher->hash(self::TEST_PASSWORD);

        // Fresh hash should not need rehash
        $this->assertFalse($this->hasher->needsRehash($hash));
    }

    public function testNeedsRehashDetectsAlgorithmChange(): void
    {
        // Create hash with bcrypt
        $bcryptHasher = new PepperedPasswordHasher(
            self::TEST_PEPPER,
            DefaultPasswordHasher::bcrypt()
        );
        $bcryptHash = $bcryptHasher->hash(self::TEST_PASSWORD);

        // Check with Argon2id hasher (different algorithm)
        $argonHasher = new PepperedPasswordHasher(
            self::TEST_PEPPER,
            DefaultPasswordHasher::argon2id()
        );

        $this->assertTrue($argonHasher->needsRehash($bcryptHash));
    }

    public function testFactoryMethodArgon2id(): void
    {
        $hasher = PepperedPasswordHasher::argon2id(self::TEST_PEPPER);

        $hash = $hasher->hash(self::TEST_PASSWORD);

        $this->assertTrue($hasher->verify(self::TEST_PASSWORD, $hash));
        $this->assertStringContainsString('$argon2id$', $hash);
    }

    public function testFactoryMethodHighSecurity(): void
    {
        $hasher = PepperedPasswordHasher::highSecurity(self::TEST_PEPPER);

        $hash = $hasher->hash(self::TEST_PASSWORD);

        $this->assertTrue($hasher->verify(self::TEST_PASSWORD, $hash));
        $this->assertStringContainsString('$argon2id$', $hash);
    }

    public function testWithCustomBaseHasher(): void
    {
        $baseHasher = DefaultPasswordHasher::bcrypt(10);
        $hasher     = new PepperedPasswordHasher(self::TEST_PEPPER, $baseHasher);

        $hash = $hasher->hash(self::TEST_PASSWORD);

        $this->assertTrue($hasher->verify(self::TEST_PASSWORD, $hash));
        $this->assertStringStartsWith('$2y$', $hash);
    }

    public function testEmptyPasswordCanBeHashed(): void
    {
        $hash = $this->hasher->hash('');

        $this->assertTrue($this->hasher->verify('', $hash));
        $this->assertFalse($this->hasher->verify('not-empty', $hash));
    }

    public function testUnicodePasswordSupport(): void
    {
        $unicodePassword = '密码🔐パスワード';

        $hash = $this->hasher->hash($unicodePassword);

        $this->assertTrue($this->hasher->verify($unicodePassword, $hash));
        $this->assertFalse($this->hasher->verify('wrong', $hash));
    }

    public function testLongPasswordSupport(): void
    {
        $longPassword = str_repeat('a', 1000);

        $hash = $this->hasher->hash($longPassword);

        $this->assertTrue($this->hasher->verify($longPassword, $hash));
        $this->assertFalse($this->hasher->verify(str_repeat('a', 999), $hash));
    }

    public function testPepperMinimumLengthIsEnforced(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Pepper must be at least 32 bytes');

        new PepperedPasswordHasher('short');
    }

    public function testPepperExactlyMinimumLengthIsAccepted(): void
    {
        $pepper32Bytes = str_repeat('a', 32);

        $hasher = new PepperedPasswordHasher($pepper32Bytes);
        $hash   = $hasher->hash('test');

        $this->assertTrue($hasher->verify('test', $hash));
    }

    public function testPepperOneByteShortOfMinimumIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new PepperedPasswordHasher(str_repeat('a', 31));
    }

    public function testFactoryMethodsEnforcePepperMinimumLength(): void
    {
        $this->expectException(InvalidArgumentException::class);

        PepperedPasswordHasher::argon2id('short');
    }

    /**
     * @throws ReflectionException
     */
    public function testDerivedKeyIsExactly32Bytes(): void
    {
        $method = new ReflectionMethod(PepperedPasswordHasher::class, 'applyPepper');

        $derived = $method->invoke($this->hasher, self::TEST_PASSWORD);

        $this->assertSame(32, strlen($derived));
    }
}
