<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Hashing;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Hashing\DefaultPasswordHasher;
use Zappzarapp\Security\Password\Hashing\HashConfig;
use Zappzarapp\Security\Password\Hashing\PasswordHasher;

#[CoversClass(DefaultPasswordHasher::class)]
final class DefaultPasswordHasherTest extends TestCase
{
    public function testImplementsPasswordHasherInterface(): void
    {
        $hasher = new DefaultPasswordHasher();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(PasswordHasher::class, $hasher);
    }

    public function testDefaultConstructorUsesDefaultConfig(): void
    {
        $hasher = new DefaultPasswordHasher();
        $hash   = $hasher->hash('testpassword');

        // Verify it hashes successfully with default Argon2id
        $this->assertStringStartsWith('$argon2id$', $hash);
    }

    public function testConstructorWithCustomConfig(): void
    {
        $config = HashConfig::bcrypt(10);
        $hasher = new DefaultPasswordHasher($config);
        $hash   = $hasher->hash('testpassword');

        $this->assertStringStartsWith('$2y$10$', $hash);
    }

    public function testHashCreatesValidHash(): void
    {
        $hasher   = new DefaultPasswordHasher();
        $password = 'MySecurePassword123!';
        $hash     = $hasher->hash($password);

        $this->assertNotEmpty($hash);
        $this->assertNotSame($password, $hash);
    }

    public function testHashCreatesDifferentHashesForSamePassword(): void
    {
        $hasher   = new DefaultPasswordHasher();
        $password = 'SamePassword';

        $hash1 = $hasher->hash($password);
        $hash2 = $hasher->hash($password);

        // Different salts should produce different hashes
        $this->assertNotSame($hash1, $hash2);
    }

    public function testVerifyReturnsTrueForCorrectPassword(): void
    {
        $hasher   = new DefaultPasswordHasher();
        $password = 'CorrectPassword!';
        $hash     = $hasher->hash($password);

        $this->assertTrue($hasher->verify($password, $hash));
    }

    public function testVerifyReturnsFalseForIncorrectPassword(): void
    {
        $hasher = new DefaultPasswordHasher();
        $hash   = $hasher->hash('CorrectPassword!');

        $this->assertFalse($hasher->verify('WrongPassword!', $hash));
    }

    public function testVerifyReturnsFalseForEmptyPassword(): void
    {
        $hasher = new DefaultPasswordHasher();
        $hash   = $hasher->hash('SomePassword');

        $this->assertFalse($hasher->verify('', $hash));
    }

    public function testHashAndVerifyWithEmptyPassword(): void
    {
        $hasher = new DefaultPasswordHasher();
        $hash   = $hasher->hash('');

        $this->assertTrue($hasher->verify('', $hash));
        $this->assertFalse($hasher->verify('notEmpty', $hash));
    }

    public function testHashAndVerifyWithUnicodePassword(): void
    {
        $hasher   = new DefaultPasswordHasher();
        $password = 'Passwort: Grossbuchstaben und Umlaute';
        $hash     = $hasher->hash($password);

        $this->assertTrue($hasher->verify($password, $hash));
    }

    public function testHashAndVerifyWithSpecialCharacters(): void
    {
        $hasher   = new DefaultPasswordHasher();
        $password = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\`~';
        $hash     = $hasher->hash($password);

        $this->assertTrue($hasher->verify($password, $hash));
    }

    public function testHashAndVerifyWithVeryLongPassword(): void
    {
        $hasher   = new DefaultPasswordHasher();
        $password = str_repeat('LongPassword!', 100);
        $hash     = $hasher->hash($password);

        $this->assertTrue($hasher->verify($password, $hash));
    }

    public function testNeedsRehashReturnsFalseForCurrentConfig(): void
    {
        $hasher = new DefaultPasswordHasher();
        $hash   = $hasher->hash('password');

        $this->assertFalse($hasher->needsRehash($hash));
    }

    public function testNeedsRehashReturnsTrueForDifferentConfig(): void
    {
        $hasher1 = new DefaultPasswordHasher(HashConfig::bcrypt(10));
        $hash    = $hasher1->hash('password');

        $hasher2 = new DefaultPasswordHasher(HashConfig::bcrypt(12));

        $this->assertTrue($hasher2->needsRehash($hash));
    }

    public function testNeedsRehashReturnsTrueForDifferentAlgorithm(): void
    {
        $bcryptHasher = new DefaultPasswordHasher(HashConfig::bcrypt());
        $hash         = $bcryptHasher->hash('password');

        $argonHasher = new DefaultPasswordHasher(HashConfig::argon2id());

        $this->assertTrue($argonHasher->needsRehash($hash));
    }

    public function testGetInfoReturnsCorrectStructure(): void
    {
        $hasher = new DefaultPasswordHasher();
        $hash   = $hasher->hash('password');

        $info = $hasher->getInfo($hash);

        $this->assertArrayHasKey('algo', $info);
        $this->assertArrayHasKey('algoName', $info);
        $this->assertArrayHasKey('options', $info);
    }

    public function testGetInfoForArgon2id(): void
    {
        $hasher = new DefaultPasswordHasher(HashConfig::argon2id());
        $hash   = $hasher->hash('password');

        $info = $hasher->getInfo($hash);

        $this->assertSame('argon2id', $info['algoName']);
        $this->assertArrayHasKey('memory_cost', $info['options']);
        $this->assertArrayHasKey('time_cost', $info['options']);
        $this->assertArrayHasKey('threads', $info['options']);
    }

    public function testGetInfoForBcrypt(): void
    {
        $hasher = new DefaultPasswordHasher(HashConfig::bcrypt(10));
        $hash   = $hasher->hash('password');

        $info = $hasher->getInfo($hash);

        $this->assertSame('bcrypt', $info['algoName']);
        $this->assertArrayHasKey('cost', $info['options']);
        $this->assertSame(10, $info['options']['cost']);
    }

    public function testArgon2idStaticFactory(): void
    {
        $hasher = DefaultPasswordHasher::argon2id();
        $hash   = $hasher->hash('password');

        $this->assertStringStartsWith('$argon2id$', $hash);
    }

    public function testBcryptStaticFactoryWithDefaultCost(): void
    {
        $hasher = DefaultPasswordHasher::bcrypt();
        $hash   = $hasher->hash('password');

        $this->assertStringStartsWith('$2y$12$', $hash);
    }

    public function testBcryptStaticFactoryWithCustomCost(): void
    {
        $hasher = DefaultPasswordHasher::bcrypt(10);
        $hash   = $hasher->hash('password');

        $this->assertStringStartsWith('$2y$10$', $hash);
    }

    public function testHighSecurityStaticFactory(): void
    {
        $hasher = DefaultPasswordHasher::highSecurity();
        $hash   = $hasher->hash('password');

        $info = $hasher->getInfo($hash);

        $this->assertSame('argon2id', $info['algoName']);
        $this->assertSame(131072, $info['options']['memory_cost']);
        $this->assertSame(6, $info['options']['time_cost']);
        $this->assertSame(2, $info['options']['threads']);
    }

    public function testVerifyWithMalformedHash(): void
    {
        $hasher = new DefaultPasswordHasher();

        $this->assertFalse($hasher->verify('password', 'not-a-valid-hash'));
    }

    public function testVerifyWithEmptyHash(): void
    {
        $hasher = new DefaultPasswordHasher();

        $this->assertFalse($hasher->verify('password', ''));
    }

    public function testNeedsRehashWithInvalidHash(): void
    {
        $hasher = new DefaultPasswordHasher();

        $this->assertTrue($hasher->needsRehash('invalid-hash'));
    }

    public function testGetInfoWithInvalidHash(): void
    {
        $hasher = new DefaultPasswordHasher();
        $info   = $hasher->getInfo('invalid-hash');

        $this->assertNull($info['algo']);
        $this->assertSame('unknown', $info['algoName']);
    }

    public function testHashWithWhitespacePassword(): void
    {
        $hasher   = new DefaultPasswordHasher();
        $password = '   spaces before and after   ';
        $hash     = $hasher->hash($password);

        $this->assertTrue($hasher->verify($password, $hash));
        $this->assertFalse($hasher->verify(trim($password), $hash));
    }

    public function testHashWithNewlineInPassword(): void
    {
        $hasher   = new DefaultPasswordHasher();
        $password = "password\nwith\nnewlines";
        $hash     = $hasher->hash($password);

        $this->assertTrue($hasher->verify($password, $hash));
    }

    public function testHashWithNullByte(): void
    {
        $hasher   = new DefaultPasswordHasher();
        $password = "password\x00withNull";
        $hash     = $hasher->hash($password);

        $this->assertTrue($hasher->verify($password, $hash));
    }

    // --- bcrypt Pre-Hashing Tests ---

    public function testBcryptWithLongPasswordOver72Bytes(): void
    {
        $hasher = DefaultPasswordHasher::bcrypt();

        // Create a password longer than 72 bytes
        $longPassword = str_repeat('A', 100);
        $this->assertGreaterThan(72, strlen($longPassword));

        $hash = $hasher->hash($longPassword);

        // Verify the full password works
        $this->assertTrue($hasher->verify($longPassword, $hash));
    }

    public function testBcryptDistinguishesLongPasswordsThatDifferAfter72Bytes(): void
    {
        $hasher = DefaultPasswordHasher::bcrypt();

        // Two passwords that are identical in first 72 bytes but differ after
        $prefix    = str_repeat('A', 72);
        $password1 = $prefix . 'suffix1';
        $password2 = $prefix . 'suffix2';

        // Without pre-hashing, bcrypt would treat these as identical
        $hash1 = $hasher->hash($password1);

        // With pre-hashing, they should be distinguishable
        $this->assertTrue($hasher->verify($password1, $hash1));
        $this->assertFalse($hasher->verify($password2, $hash1));
    }

    public function testBcryptPreHashingDoesNotAffectShortPasswords(): void
    {
        $hasher = DefaultPasswordHasher::bcrypt();

        $shortPassword = 'ShortPassword123!';
        $this->assertLessThan(72, strlen($shortPassword));

        $hash = $hasher->hash($shortPassword);

        $this->assertTrue($hasher->verify($shortPassword, $hash));
        $this->assertFalse($hasher->verify('DifferentPassword', $hash));
    }

    public function testArgon2idHandlesLongPasswordsNatively(): void
    {
        $hasher = DefaultPasswordHasher::argon2id();

        // Argon2id has no length limit, pre-hashing is not applied
        $longPassword = str_repeat('B', 200);

        $hash = $hasher->hash($longPassword);

        $this->assertTrue($hasher->verify($longPassword, $hash));
    }

    public function testBcryptPreHashingWithExactly72BytePassword(): void
    {
        $hasher = DefaultPasswordHasher::bcrypt();

        $password72 = str_repeat('X', 72);
        $this->assertSame(72, strlen($password72));

        $hash = $hasher->hash($password72);

        $this->assertTrue($hasher->verify($password72, $hash));
        $this->assertFalse($hasher->verify($password72 . 'extra', $hash));
    }

    public function testBcryptPreHashingWithUnicodeExceeding72Bytes(): void
    {
        $hasher = DefaultPasswordHasher::bcrypt();

        // Unicode characters that exceed 72 bytes when UTF-8 encoded
        $unicodePassword = str_repeat("\u{1F600}", 20); // 20 emoji = 80 bytes in UTF-8
        $this->assertGreaterThan(72, strlen($unicodePassword));

        $hash = $hasher->hash($unicodePassword);

        $this->assertTrue($hasher->verify($unicodePassword, $hash));
    }
}
