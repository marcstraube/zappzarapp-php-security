<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Encryption;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Encryption\Ciphertext;
use Zappzarapp\Security\Encryption\EncryptionKey;
use Zappzarapp\Security\Encryption\Exception\DecryptionException;
use Zappzarapp\Security\Encryption\SymmetricEncryptor;
use Zappzarapp\Security\Secrets\SecretValue;

#[CoversClass(SymmetricEncryptor::class)]
#[CoversClass(DecryptionException::class)]
#[UsesClass(Ciphertext::class)]
#[UsesClass(EncryptionKey::class)]
#[UsesClass(SecretValue::class)]
final class SymmetricEncryptorTest extends TestCase
{
    private SymmetricEncryptor $encryptor;

    private EncryptionKey $key;

    protected function setUp(): void
    {
        $this->encryptor = new SymmetricEncryptor();
        $this->key       = EncryptionKey::generate();
    }

    #[Test]
    public function testRoundTrip(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example', $this->key);

        $this->assertSame('plaintext-example', $this->encryptor->decrypt($ciphertext, $this->key));
    }

    #[Test]
    public function testRoundTripWithAdditionalData(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example', $this->key, 'user:42');

        $this->assertSame(
            'plaintext-example',
            $this->encryptor->decrypt($ciphertext, $this->key, 'user:42')
        );
    }

    #[Test]
    public function testRoundTripWithEmptyPlaintext(): void
    {
        $ciphertext = $this->encryptor->encrypt('', $this->key);

        $this->assertSame('', $this->encryptor->decrypt($ciphertext, $this->key));
    }

    #[Test]
    public function testRoundTripWithBinaryPlaintext(): void
    {
        $plaintext = random_bytes(256);

        $ciphertext = $this->encryptor->encrypt($plaintext, $this->key);

        $this->assertSame($plaintext, $this->encryptor->decrypt($ciphertext, $this->key));
    }

    #[Test]
    public function testRoundTripViaStringForm(): void
    {
        $stored = $this->encryptor->encrypt('plaintext-example', $this->key)->toString();

        $this->assertSame(
            'plaintext-example',
            $this->encryptor->decrypt(Ciphertext::fromString($stored), $this->key)
        );
    }

    #[Test]
    public function testCiphertextDoesNotContainPlaintext(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example', $this->key);

        $this->assertStringNotContainsString('plaintext-example', $ciphertext->toBinary());
    }

    #[Test]
    public function testEncryptUsesUniqueNonces(): void
    {
        $first  = $this->encryptor->encrypt('plaintext-example', $this->key);
        $second = $this->encryptor->encrypt('plaintext-example', $this->key);

        $this->assertNotSame($first->nonce, $second->nonce);
        $this->assertNotSame($first->payload, $second->payload);
    }

    #[Test]
    public function testDecryptRejectsTamperedPayload(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example', $this->key);
        $tampered   = new Ciphertext($ciphertext->nonce, $this->flipLastByte($ciphertext->payload));

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage(
            'Decryption failed (wrong key, tampered ciphertext, or mismatched additional data)'
        );

        $this->encryptor->decrypt($tampered, $this->key);
    }

    #[Test]
    public function testDecryptRejectsTamperedNonce(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example', $this->key);
        $tampered   = new Ciphertext($this->flipLastByte($ciphertext->nonce), $ciphertext->payload);

        $this->expectException(DecryptionException::class);

        $this->encryptor->decrypt($tampered, $this->key);
    }

    #[Test]
    public function testDecryptRejectsWrongKey(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example', $this->key);

        $this->expectException(DecryptionException::class);

        $this->encryptor->decrypt($ciphertext, EncryptionKey::generate());
    }

    #[Test]
    public function testDecryptRejectsMismatchedAdditionalData(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example', $this->key, 'user:42');

        $this->expectException(DecryptionException::class);

        $this->encryptor->decrypt($ciphertext, $this->key, 'user:43');
    }

    #[Test]
    public function testDecryptRejectsMissingAdditionalData(): void
    {
        $ciphertext = $this->encryptor->encrypt('plaintext-example', $this->key, 'user:42');

        $this->expectException(DecryptionException::class);

        $this->encryptor->decrypt($ciphertext, $this->key);
    }

    private function flipLastByte(string $bytes): string
    {
        $lastIndex         = strlen($bytes) - 1;
        $bytes[$lastIndex] = chr(ord($bytes[$lastIndex]) ^ 0xFF);

        return $bytes;
    }
}
