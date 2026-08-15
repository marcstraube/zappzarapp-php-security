<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Totp;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Secrets\SecretValue;
use Zappzarapp\Security\Totp\Encoding\Base32;
use Zappzarapp\Security\Totp\Exception\InvalidProvisioningDataException;
use Zappzarapp\Security\Totp\ProvisioningUri;
use Zappzarapp\Security\Totp\TotpAlgorithm;
use Zappzarapp\Security\Totp\TotpConfig;
use Zappzarapp\Security\Totp\TotpSecret;

#[CoversClass(ProvisioningUri::class)]
#[CoversClass(InvalidProvisioningDataException::class)]
#[UsesClass(Base32::class)]
#[UsesClass(TotpAlgorithm::class)]
#[UsesClass(TotpConfig::class)]
#[UsesClass(TotpSecret::class)]
#[UsesClass(SecretValue::class)]
final class ProvisioningUriTest extends TestCase
{
    private const string SECRET_BYTES = '12345678901234567890';

    #[Test]
    public function testToStringProducesKeyUriFormat(): void
    {
        $uri = new ProvisioningUri('Example App', 'marc@example.com', new TotpSecret(self::SECRET_BYTES));

        $this->assertSame(
            'otpauth://totp/Example%20App:marc%40example.com'
                . '?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
                . '&issuer=Example%20App'
                . '&algorithm=SHA1&digits=6&period=30',
            $uri->toString()
        );
    }

    #[Test]
    public function testToStringReflectsCustomConfig(): void
    {
        $uri = new ProvisioningUri(
            'Example',
            'marc',
            new TotpSecret(self::SECRET_BYTES),
            new TotpConfig(period: 60, digits: 8, algorithm: TotpAlgorithm::Sha256)
        );

        $this->assertStringContainsString('algorithm=SHA256', $uri->toString());
        $this->assertStringContainsString('digits=8', $uri->toString());
        $this->assertStringContainsString('period=60', $uri->toString());
    }

    #[Test]
    public function testSecretIsBase32Encoded(): void
    {
        $secret = TotpSecret::generate();

        $uri = new ProvisioningUri('Example', 'marc', $secret);

        $this->assertStringContainsString('secret=' . $secret->toBase32(), $uri->toString());
    }

    #[Test]
    public function testRejectsEmptyIssuer(): void
    {
        $this->expectException(InvalidProvisioningDataException::class);
        $this->expectExceptionMessage('Provisioning issuer must not be empty');

        new ProvisioningUri('', 'marc', new TotpSecret(self::SECRET_BYTES));
    }

    #[Test]
    public function testRejectsEmptyAccountName(): void
    {
        $this->expectException(InvalidProvisioningDataException::class);
        $this->expectExceptionMessage('Provisioning account name must not be empty');

        new ProvisioningUri('Example', '', new TotpSecret(self::SECRET_BYTES));
    }

    #[Test]
    public function testRejectsControlCharactersInIssuer(): void
    {
        $this->expectException(InvalidProvisioningDataException::class);
        $this->expectExceptionMessage('Provisioning issuer must not contain control characters');

        new ProvisioningUri("Example\nApp", 'marc', new TotpSecret(self::SECRET_BYTES));
    }

    #[Test]
    public function testRejectsControlCharactersInAccountName(): void
    {
        $this->expectException(InvalidProvisioningDataException::class);
        $this->expectExceptionMessage('Provisioning account name must not contain control characters');

        new ProvisioningUri('Example', "marc\r", new TotpSecret(self::SECRET_BYTES));
    }

    #[Test]
    public function testRejectsColonInIssuer(): void
    {
        $this->expectException(InvalidProvisioningDataException::class);
        $this->expectExceptionMessage('Provisioning issuer must not contain a colon (label delimiter)');

        new ProvisioningUri('Example: App', 'marc', new TotpSecret(self::SECRET_BYTES));
    }

    #[Test]
    public function testRejectsColonInAccountName(): void
    {
        $this->expectException(InvalidProvisioningDataException::class);
        $this->expectExceptionMessage('Provisioning account name must not contain a colon (label delimiter)');

        new ProvisioningUri('Example', 'acct:marc', new TotpSecret(self::SECRET_BYTES));
    }
}
