<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Nonce;

use PHPUnit\Framework\TestCase;
use Random\RandomException;
use Zappzarapp\Security\Csp\Nonce\NonceProvider;
use Zappzarapp\Security\Csp\Nonce\NullNonce;

final class NullNonceTest extends TestCase
{
    public function testImplementsNonceProvider(): void
    {
        $nullNonce = new NullNonce();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(NonceProvider::class, $nullNonce);
    }

    /**
     * @throws RandomException
     */
    public function testReturnsEmptyString(): void
    {
        $nullNonce = new NullNonce();

        $this->assertSame('', $nullNonce->get());
    }

    /**
     * @throws RandomException
     */
    public function testAlwaysReturnsEmptyString(): void
    {
        $nullNonce = new NullNonce();

        // Call multiple times to ensure consistent behavior
        $this->assertSame('', $nullNonce->get());
        $this->assertSame('', $nullNonce->get());
        $this->assertSame('', $nullNonce->get());
    }
}
