<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp\Recovery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Hashing\DefaultPasswordHasher;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\Totp\Recovery\RecoveryCode;
use Zappzarapp\Security\Totp\Recovery\RecoveryCodeVerifier;

#[CoversClass(RecoveryCodeVerifier::class)]
#[UsesClass(RecoveryCode::class)]
#[UsesClass(DefaultPasswordHasher::class)]
#[UsesClass(SecretValue::class)]
final class RecoveryCodeVerifierTest extends TestCase
{
    private RecoveryCodeVerifier $verifier;

    protected function setUp(): void
    {
        $this->verifier = new RecoveryCodeVerifier();
    }

    #[Test]
    public function testHashProducesArgon2idHash(): void
    {
        $hash = $this->verifier->hash(new RecoveryCode('abcd-efgh-jkmn-pqrs'));

        $this->assertStringStartsWith('$argon2id$', $hash);
    }

    #[Test]
    public function testVerifyReturnsIndexOfMatchingHash(): void
    {
        $hashes = [
            $this->verifier->hash(new RecoveryCode('abcd-efgh-jkmn-pqrs')),
            $this->verifier->hash(new RecoveryCode('tuvw-xyz2-3456-789a')),
        ];

        $this->assertSame(1, $this->verifier->verify('tuvw-xyz2-3456-789a', $hashes));
    }

    #[Test]
    public function testVerifyIgnoresCaseAndSeparators(): void
    {
        $hashes = [$this->verifier->hash(new RecoveryCode('abcd-efgh-jkmn-pqrs'))];

        $this->assertSame(0, $this->verifier->verify('ABCD EFGH jkmn.pqrs', $hashes));
    }

    #[Test]
    public function testVerifyReturnsNullForWrongCode(): void
    {
        $hashes = [$this->verifier->hash(new RecoveryCode('abcd-efgh-jkmn-pqrs'))];

        $this->assertNull($this->verifier->verify('wwww-wwww-wwww-wwww', $hashes));
    }

    #[Test]
    public function testVerifyReturnsNullForEmptyNormalizedInput(): void
    {
        $hashes = [$this->verifier->hash(new RecoveryCode('abcd-efgh-jkmn-pqrs'))];

        $this->assertNull($this->verifier->verify('--- ___', $hashes));
    }

    #[Test]
    public function testVerifyReturnsNullForEmptyHashList(): void
    {
        $this->assertNull($this->verifier->verify('abcd-efgh-jkmn-pqrs', []));
    }

    #[Test]
    public function testEmptyInputNeverMatchesHashOfEmptyNormalizedCode(): void
    {
        $hashes = [$this->verifier->hash(new RecoveryCode('***'))];

        $this->assertNull($this->verifier->verify('---', $hashes));
    }

    #[Test]
    public function testVerifyPreservesOriginalArrayKeys(): void
    {
        $hashes = [
            7  => $this->verifier->hash(new RecoveryCode('abcd-efgh-jkmn-pqrs')),
            42 => $this->verifier->hash(new RecoveryCode('tuvw-xyz2-3456-789a')),
        ];

        $this->assertSame(42, $this->verifier->verify('tuvw-xyz2-3456-789a', $hashes));
    }
}
