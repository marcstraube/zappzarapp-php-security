<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Nonce;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;
use Zappzarapp\Security\Csp\Nonce\NonceProvider;

final class NonceGeneratorTest extends TestCase
{
    #[Test]
    public function testImplementsNonceProvider(): void
    {
        $generator = new NonceGenerator();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(NonceProvider::class, $generator);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGetGeneratesBase64EncodedString(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();

        $this->assertIsString($nonce);
        $this->assertNotEmpty($nonce);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9+\/=]+$/', $nonce);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGetReturnsSameNonceForSameInstance(): void
    {
        $generator = new NonceGenerator();

        $nonce1 = $generator->get();
        $nonce2 = $generator->get();

        $this->assertSame($nonce1, $nonce2);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGetReturnsCachedNonceWithoutRegeneration(): void
    {
        $generator = new NonceGenerator();

        // First call generates and caches
        $firstNonce = $generator->get();

        // Second call should return the same cached value
        $secondNonce = $generator->get();

        // Third call should still return the same
        $thirdNonce = $generator->get();

        $this->assertSame($firstNonce, $secondNonce);
        $this->assertSame($firstNonce, $thirdNonce);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testGeneratedNonceHasCorrectLength(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();

        // 32 bytes base64 encoded = 44 characters (including padding)
        // base64 encoding: ceil(32 * 4 / 3) = 43, padded to multiple of 4 = 44
        $this->assertSame(44, strlen($nonce));
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testSetOverridesGeneratedNonce(): void
    {
        $generator = new NonceGenerator();
        $generated = $generator->get();
        $custom    = 'custom-nonce-value';

        $generator->set($custom);

        $this->assertSame($custom, $generator->get());
        $this->assertNotSame($generated, $generator->get());
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testResetClearsNonce(): void
    {
        $generator = new NonceGenerator();

        $nonce1 = $generator->get();
        $generator->reset();
        $nonce2 = $generator->get();

        $this->assertNotSame($nonce1, $nonce2);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testSeparateInstancesHaveDifferentNonces(): void
    {
        $generator1 = new NonceGenerator();
        $generator2 = new NonceGenerator();

        $nonce1 = $generator1->get();
        $nonce2 = $generator2->get();

        $this->assertNotSame($nonce1, $nonce2);
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testNonceIsBase64Encoded(): void
    {
        $generator = new NonceGenerator();
        $nonce     = $generator->get();

        // Valid base64 should decode and re-encode to same value
        $decoded = base64_decode($nonce, true);
        $this->assertNotFalse($decoded);
        $this->assertSame($nonce, base64_encode($decoded));
    }

    // Validation Tests (Defense in Depth)
    #[Test]
    public function testSetRejectsEmptyNonce(): void
    {
        $generator = new NonceGenerator();

        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('cannot be empty');

        $generator->set('');
    }

    #[Test]
    public function testSetRejectsSemicolon(): void
    {
        $generator = new NonceGenerator();

        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains semicolon');

        $generator->set("valid'; script-src 'unsafe-inline");
    }

    #[Test]
    public function testSetRejectsNewline(): void
    {
        $generator = new NonceGenerator();

        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains control character');

        $generator->set("valid\nX-Injected-Header: malicious");
    }

    #[Test]
    public function testSetRejectsCarriageReturn(): void
    {
        $generator = new NonceGenerator();

        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains control character');

        $generator->set("valid\rX-Injected-Header: malicious");
    }

    #[Test]
    public function testSetRejectsSingleQuote(): void
    {
        $generator = new NonceGenerator();

        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains single quote');

        $generator->set("valid' 'unsafe-inline");
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testSetAcceptsValidBase64Nonce(): void
    {
        $generator  = new NonceGenerator();
        $validNonce = 'dGVzdC1ub25jZS12YWx1ZQ==';

        $generator->set($validNonce);

        $this->assertSame($validNonce, $generator->get());
    }

    /**
     * @throws RandomException
     */
    #[Test]
    public function testSetAcceptsAlphanumericNonce(): void
    {
        $generator  = new NonceGenerator();
        $validNonce = 'abc123XYZ789';

        $generator->set($validNonce);

        $this->assertSame($validNonce, $generator->get());
    }

    #[Test]
    public function testSetRejectsSpace(): void
    {
        $generator = new NonceGenerator();

        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains space');

        $generator->set("abc unsafe-inline");
    }

    #[Test]
    public function testSetRejectsSpaceAtStart(): void
    {
        $generator = new NonceGenerator();

        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains space');

        $generator->set(" leadingspace");
    }

    #[Test]
    public function testSetRejectsSpaceAtEnd(): void
    {
        $generator = new NonceGenerator();

        $this->expectException(InvalidDirectiveValueException::class);
        $this->expectExceptionMessage('contains space');

        $generator->set("trailingspace ");
    }
}
