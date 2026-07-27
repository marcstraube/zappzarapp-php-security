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
use Zappzarapp\Security\Encryption\EnvelopeCiphertext;
use Zappzarapp\Security\Encryption\EnvelopeEncryptor;
use Zappzarapp\Security\Encryption\Exception\DecryptionException;
use Zappzarapp\Security\Encryption\SymmetricEncryptor;
use Zappzarapp\Security\Secrets\SecretValue;

#[CoversClass(EnvelopeEncryptor::class)]
#[UsesClass(Ciphertext::class)]
#[UsesClass(EncryptionKey::class)]
#[UsesClass(EnvelopeCiphertext::class)]
#[UsesClass(SymmetricEncryptor::class)]
#[UsesClass(DecryptionException::class)]
#[UsesClass(SecretValue::class)]
final class EnvelopeEncryptorTest extends TestCase
{
    private EnvelopeEncryptor $encryptor;

    private EncryptionKey $keyEncryptionKey;

    protected function setUp(): void
    {
        $this->encryptor        = new EnvelopeEncryptor();
        $this->keyEncryptionKey = EncryptionKey::generate();
    }

    #[Test]
    public function testRoundTrip(): void
    {
        $sealed = $this->encryptor->seal('document-content', $this->keyEncryptionKey);

        $this->assertSame(
            'document-content',
            $this->encryptor->open($sealed, $this->keyEncryptionKey)
        );
    }

    #[Test]
    public function testRoundTripWithAdditionalData(): void
    {
        $sealed = $this->encryptor->seal('document-content', $this->keyEncryptionKey, 'doc:17');

        $this->assertSame(
            'document-content',
            $this->encryptor->open($sealed, $this->keyEncryptionKey, 'doc:17')
        );
    }

    #[Test]
    public function testRoundTripViaStringForm(): void
    {
        $stored = $this->encryptor->seal('document-content', $this->keyEncryptionKey)->toString();

        $this->assertSame(
            'document-content',
            $this->encryptor->open(EnvelopeCiphertext::fromString($stored), $this->keyEncryptionKey)
        );
    }

    #[Test]
    public function testSealUsesUniqueDataKeys(): void
    {
        $first  = $this->encryptor->seal('document-content', $this->keyEncryptionKey);
        $second = $this->encryptor->seal('document-content', $this->keyEncryptionKey);

        $this->assertNotSame(
            $first->wrappedKey->payload,
            $second->wrappedKey->payload
        );
        $this->assertNotSame($first->payload->payload, $second->payload->payload);
    }

    #[Test]
    public function testOpenRejectsWrongKeyEncryptionKey(): void
    {
        $sealed = $this->encryptor->seal('document-content', $this->keyEncryptionKey);

        $this->expectException(DecryptionException::class);

        $this->encryptor->open($sealed, EncryptionKey::generate());
    }

    #[Test]
    public function testOpenRejectsTamperedWrappedKey(): void
    {
        $sealed   = $this->encryptor->seal('document-content', $this->keyEncryptionKey);
        $tampered = new EnvelopeCiphertext(
            new Ciphertext($sealed->wrappedKey->nonce, $this->flipLastByte($sealed->wrappedKey->payload)),
            $sealed->payload
        );

        $this->expectException(DecryptionException::class);

        $this->encryptor->open($tampered, $this->keyEncryptionKey);
    }

    #[Test]
    public function testOpenRejectsTamperedPayload(): void
    {
        $sealed   = $this->encryptor->seal('document-content', $this->keyEncryptionKey);
        $tampered = new EnvelopeCiphertext(
            $sealed->wrappedKey,
            new Ciphertext($sealed->payload->nonce, $this->flipLastByte($sealed->payload->payload))
        );

        $this->expectException(DecryptionException::class);

        $this->encryptor->open($tampered, $this->keyEncryptionKey);
    }

    #[Test]
    public function testOpenRejectsMismatchedAdditionalData(): void
    {
        $sealed = $this->encryptor->seal('document-content', $this->keyEncryptionKey, 'doc:17');

        $this->expectException(DecryptionException::class);

        $this->encryptor->open($sealed, $this->keyEncryptionKey, 'doc:18');
    }

    #[Test]
    public function testOpenRejectsSwappedEnvelopeParts(): void
    {
        $first  = $this->encryptor->seal('first-document', $this->keyEncryptionKey);
        $second = $this->encryptor->seal('second-document', $this->keyEncryptionKey);

        $mixed = new EnvelopeCiphertext($first->wrappedKey, $second->payload);

        $this->expectException(DecryptionException::class);

        $this->encryptor->open($mixed, $this->keyEncryptionKey);
    }

    private function flipLastByte(string $bytes): string
    {
        $lastIndex         = strlen($bytes) - 1;
        $bytes[$lastIndex] = chr(ord($bytes[$lastIndex]) ^ 0xFF);

        return $bytes;
    }
}
