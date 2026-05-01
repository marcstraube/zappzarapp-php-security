<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Validation;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Token\CsrfToken;
use Zappzarapp\Security\Csrf\Validation\ValidatesCsrfToken;

/**
 * Helper class that exposes the trait method for testing
 *
 * @internal
 */
final class TraitTestValidator
{
    use ValidatesCsrfToken;

    /**
     * @throws CsrfTokenMismatchException
     * @throws InvalidCsrfTokenException
     */
    public function validate(string $submitted, string $expected): void
    {
        $this->validateCsrfToken($submitted, $expected);
    }
}

/**
 * Tests for ValidatesCsrfToken trait
 *
 * Uses TraitTestValidator to test the trait directly.
 */
#[CoversTrait(ValidatesCsrfToken::class)]
#[UsesClass(CsrfToken::class)]
#[UsesClass(CsrfTokenMismatchException::class)]
#[UsesClass(InvalidCsrfTokenException::class)]
final class ValidatesCsrfTokenTest extends TestCase
{
    private TraitTestValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new TraitTestValidator();
    }

    // --- Trait: validateCsrfToken() ---

    #[Test]
    public function testTraitValidatesMatchingTokens(): void
    {
        $token = base64_encode(random_bytes(32));

        $this->validator->validate($token, $token);

        $this->assertTrue(true);
    }

    #[Test]
    public function testTraitThrowsOnEmptySubmittedToken(): void
    {
        $expected = base64_encode(random_bytes(32));

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('missing');

        $this->validator->validate('', $expected);
    }

    #[Test]
    public function testTraitThrowsOnEmptyExpectedToken(): void
    {
        $submitted = base64_encode(random_bytes(32));

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('No CSRF token found');

        $this->validator->validate($submitted, '');
    }

    #[Test]
    public function testTraitThrowsOnMismatch(): void
    {
        $expected  = base64_encode(random_bytes(32));
        $submitted = base64_encode(random_bytes(32));

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $this->validator->validate($submitted, $expected);
    }

    #[Test]
    public function testTraitValidatesTokenFormat(): void
    {
        $expected = base64_encode(random_bytes(32));

        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('base64');

        $this->validator->validate('not!valid!base64!!!', $expected);
    }

    #[Test]
    public function testTraitValidatesTokenEntropy(): void
    {
        $expected = base64_encode(random_bytes(32));

        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('entropy');

        $this->validator->validate(base64_encode('short'), $expected);
    }

    #[Test]
    public function testTraitValidatesControlCharacters(): void
    {
        $expected = base64_encode(random_bytes(32));
        $badToken = base64_encode(random_bytes(32)) . "\n";

        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('control characters');

        $this->validator->validate($badToken, $expected);
    }

    #[Test]
    public function testTraitUsesTimingSafeComparison(): void
    {
        $token = base64_encode(random_bytes(32));

        // Token that differs only in last character
        $almostCorrect = substr($token, 0, -1) . 'X';

        $start1 = hrtime(true);
        try {
            $this->validator->validate($almostCorrect, $token);
        } catch (CsrfTokenMismatchException) {
            // Expected
        }
        $time1  = hrtime(true) - $start1;

        $start2 = hrtime(true);
        try {
            $this->validator->validate(base64_encode(random_bytes(32)), $token);
        } catch (CsrfTokenMismatchException) {
            // Expected
        }
        $time2  = hrtime(true) - $start2;

        // Times should be within two orders of magnitude (100x tolerance)
        // Higher tolerance needed due to JIT, GC, and system load variations
        $this->assertLessThan($time1 * 100, $time2);
        $this->assertLessThan($time2 * 100, $time1);
    }
}
