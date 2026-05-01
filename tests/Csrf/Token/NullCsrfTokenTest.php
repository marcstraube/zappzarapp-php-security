<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Token;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\Token\CsrfToken;
use Zappzarapp\Security\Csrf\Token\CsrfTokenProvider;
use Zappzarapp\Security\Csrf\Token\NullCsrfToken;

#[CoversClass(NullCsrfToken::class)]
final class NullCsrfTokenTest extends TestCase
{
    // Note: Tests run in PHPUnit, so NullCsrfToken automatically detects test environment

    #[Test]
    public function testImplementsCsrfTokenProvider(): void
    {
        $provider = new NullCsrfToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(CsrfTokenProvider::class, $provider);
    }

    #[Test]
    public function testGetReturnsCsrfToken(): void
    {
        $provider = new NullCsrfToken();
        $token    = $provider->get();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfToken::class, $token);
    }

    #[Test]
    public function testGetReturnsSameTokenEveryTime(): void
    {
        $provider = new NullCsrfToken();

        $token1 = $provider->get();
        $token2 = $provider->get();
        $token3 = $provider->get();

        $this->assertSame($token1->value(), $token2->value());
        $this->assertSame($token2->value(), $token3->value());
    }

    #[Test]
    public function testDefaultTokenMeetsMinimumRequirements(): void
    {
        $provider = new NullCsrfToken();
        $token    = $provider->get();
        $bytes    = $token->rawBytes();

        $this->assertGreaterThanOrEqual(CsrfToken::MIN_BYTES, strlen($bytes));
    }

    #[Test]
    public function testCustomTokenIsUsed(): void
    {
        $customValue = base64_encode(random_bytes(32));
        $provider    = new NullCsrfToken($customValue);
        $token       = $provider->get();

        $this->assertSame($customValue, $token->value());
    }

    #[Test]
    public function testResetDoesNotChangeToken(): void
    {
        $provider = new NullCsrfToken();
        $token1   = $provider->get();

        $provider->reset();

        $token2 = $provider->get();

        $this->assertSame($token1->value(), $token2->value());
    }

    #[Test]
    public function testResetIsNoOp(): void
    {
        $provider = new NullCsrfToken();

        // Should not throw
        $provider->reset();
        $provider->reset();
        $provider->reset();

        $this->assertTrue(true);
    }

    #[Test]
    public function testTokenValidationPassesForNullToken(): void
    {
        $provider = new NullCsrfToken();
        $token    = $provider->get();

        // Token should be valid base64 with sufficient entropy
        $this->assertNotEmpty($token->value());
        $this->assertSame(base64_encode($token->rawBytes()), $token->value());
    }

    // --- Environment Detection ---

    #[Test]
    public function testAllowsInstantiationInTestEnvironment(): void
    {
        // PHPUnit is running, so this should work without explicit allowProduction
        $provider = new NullCsrfToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies environment detection */
        $this->assertInstanceOf(NullCsrfToken::class, $provider);
    }

    #[Test]
    public function testAllowProductionBypassesEnvironmentCheck(): void
    {
        // Explicit allowProduction flag should work regardless of environment
        $provider = new NullCsrfToken(allowProduction: true);

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies bypass works */
        $this->assertInstanceOf(NullCsrfToken::class, $provider);
    }

    #[Test]
    public function testCustomTokenWithAllowProduction(): void
    {
        $customValue = base64_encode(random_bytes(32));
        $provider    = new NullCsrfToken($customValue, allowProduction: true);

        $this->assertSame($customValue, $provider->get()->value());
    }
}
