<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp\Recovery;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\Totp\Recovery\RecoveryCode;

#[CoversClass(RecoveryCode::class)]
#[UsesClass(SecretValue::class)]
final class RecoveryCodeTest extends TestCase
{
    #[Test]
    public function testRevealReturnsPlainText(): void
    {
        $this->assertSame('abcd-efgh-jkmn-pqrs', (new RecoveryCode('abcd-efgh-jkmn-pqrs'))->reveal());
    }

    #[Test]
    public function testNormalizedStripsSeparators(): void
    {
        $this->assertSame('abcdefghjkmnpqrs', (new RecoveryCode('abcd-efgh-jkmn-pqrs'))->normalized());
    }

    #[Test]
    public function testNormalizeLowercasesAndStripsNonAlphanumerics(): void
    {
        $this->assertSame('abcd2345', RecoveryCode::normalize(' AB cd-23_45 '));
    }

    #[Test]
    public function testNormalizeOfGarbageIsEmpty(): void
    {
        $this->assertSame('', RecoveryCode::normalize('---   ___'));
    }

    #[Test]
    public function testDebugOutputIsRedacted(): void
    {
        $this->assertSame(
            ['plainText' => '***REDACTED***'],
            (new RecoveryCode('abcd-efgh-jkmn-pqrs'))->__debugInfo()
        );
    }
}
