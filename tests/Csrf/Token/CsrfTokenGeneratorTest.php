<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Token;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Zappzarapp\Security\Csrf\Token\CsrfToken;
use Zappzarapp\Security\Csrf\Token\CsrfTokenGenerator;
use Zappzarapp\Security\Csrf\Token\CsrfTokenProvider;

#[CoversClass(CsrfTokenGenerator::class)]
#[UsesClass(CsrfToken::class)]
final class CsrfTokenGeneratorTest extends TestCase
{
    #[Test]
    public function testImplementsCsrfTokenProvider(): void
    {
        $generator = new CsrfTokenGenerator();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(CsrfTokenProvider::class, $generator);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGetReturnsCsrfToken(): void
    {
        $generator = new CsrfTokenGenerator();
        $token     = $generator->get();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfToken::class, $token);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGetReturnsSameTokenOnMultipleCalls(): void
    {
        $generator = new CsrfTokenGenerator();

        $token1 = $generator->get();
        $token2 = $generator->get();

        $this->assertSame($token1->value(), $token2->value());
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGenerateReturnsNewToken(): void
    {
        $generator = new CsrfTokenGenerator();

        $token1 = $generator->generate();
        $token2 = $generator->generate();

        $this->assertNotSame($token1->value(), $token2->value());
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGenerateReturnsValidBase64(): void
    {
        $generator = new CsrfTokenGenerator();
        $token     = $generator->generate();

        $decoded = base64_decode($token->value(), true);
        $this->assertNotFalse($decoded);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGenerateUsesMinimumBytes(): void
    {
        $generator = new CsrfTokenGenerator(bytes: 16);
        $token     = $generator->generate();

        $decoded = base64_decode($token->value(), true);
        $this->assertNotFalse($decoded);
        $this->assertGreaterThanOrEqual(CsrfToken::MIN_BYTES, strlen($decoded));
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGenerateWithCustomBytes(): void
    {
        $generator = new CsrfTokenGenerator(bytes: 64);
        $token     = $generator->generate();

        $decoded = base64_decode($token->value(), true);
        $this->assertNotFalse($decoded);
        $this->assertSame(64, strlen($decoded));
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testResetClearsToken(): void
    {
        $generator = new CsrfTokenGenerator();

        $token1 = $generator->get();
        $generator->reset();
        $token2 = $generator->get();

        $this->assertNotSame($token1->value(), $token2->value());
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testSetOverridesToken(): void
    {
        $generator = new CsrfTokenGenerator();
        $custom    = new CsrfToken(base64_encode(random_bytes(32)));

        $generator->set($custom);

        $this->assertSame($custom->value(), $generator->get()->value());
    }

    #[Test]
    public function testDefaultBytesConstant(): void
    {
        $this->assertSame(32, CsrfTokenGenerator::DEFAULT_BYTES);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGetAfterSetReturnsSetToken(): void
    {
        $generator = new CsrfTokenGenerator();
        $custom    = new CsrfToken(base64_encode(random_bytes(32)));

        $generator->get();
        $generator->set($custom);
        $result = $generator->get();

        $this->assertSame($custom->value(), $result->value());
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testDifferentInstancesGenerateDifferentTokens(): void
    {
        $generator1 = new CsrfTokenGenerator();
        $generator2 = new CsrfTokenGenerator();

        $token1 = $generator1->get();
        $token2 = $generator2->get();

        $this->assertNotSame($token1->value(), $token2->value());
    }
}
