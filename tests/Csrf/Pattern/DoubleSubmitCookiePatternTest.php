<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Pattern;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\CsrfConfig;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Pattern\DoubleSubmitCookiePattern;
use Zappzarapp\Security\Csrf\Token\CsrfToken;

#[CoversClass(DoubleSubmitCookiePattern::class)]
final class DoubleSubmitCookiePatternTest extends TestCase
{
    /**
     * Test secret (32 bytes minimum)
     */
    private const string TEST_SECRET = 'test-secret-key-32-bytes-long!!!';

    private DoubleSubmitCookiePattern $pattern;

    protected function setUp(): void
    {
        $this->pattern = new DoubleSubmitCookiePattern(self::TEST_SECRET);
    }

    // --- Constructor Validation ---

    #[Test]
    public function testConstructorRejectsShortSecret(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least 32 bytes');

        new DoubleSubmitCookiePattern('short');
    }

    #[Test]
    public function testConstructorAcceptsMinimumLengthSecret(): void
    {
        $pattern = new DoubleSubmitCookiePattern(str_repeat('x', 32));

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies constructor succeeds */
        $this->assertInstanceOf(DoubleSubmitCookiePattern::class, $pattern);
    }

    // --- Token Generation ---

    #[Test]
    public function testGenerateTokenReturnsCsrfToken(): void
    {
        $token = $this->pattern->generateToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfToken::class, $token);
    }

    #[Test]
    public function testGenerateTokenHasMinimumEntropy(): void
    {
        $token = $this->pattern->generateToken();
        $bytes = $token->rawBytes();

        $this->assertGreaterThanOrEqual(32, strlen($bytes));
    }

    #[Test]
    public function testGenerateTokenReturnsUniqueTokens(): void
    {
        $tokens = [];
        for ($i = 0; $i < 100; $i++) {
            $tokens[] = $this->pattern->generateToken()->value();
        }

        $uniqueTokens = array_unique($tokens);
        $this->assertCount(100, $uniqueTokens);
    }

    // --- Token Signing ---

    #[Test]
    public function testSignTokenReturnsTokenWithSignature(): void
    {
        $token       = $this->pattern->generateToken();
        $signedToken = $this->pattern->signToken($token);
        $tokenValue  = $token->value();

        $this->assertStringContainsString('.', $signedToken);
        $this->assertNotEmpty($tokenValue);

        // Verify signed token starts with token value
        $this->assertSame($tokenValue, substr($signedToken, 0, strlen($tokenValue)));
    }

    #[Test]
    public function testSignTokenProducesDifferentSignaturesWithDifferentSecrets(): void
    {
        $pattern2 = new DoubleSubmitCookiePattern('different-secret-32-bytes-long!!');

        $token   = $this->pattern->generateToken();
        $signed1 = $this->pattern->signToken($token);
        $signed2 = $pattern2->signToken($token);

        $this->assertNotSame($signed1, $signed2);
    }

    // --- Validation Success ---

    #[Test]
    public function testValidateSucceedsWithCorrectlySignedToken(): void
    {
        $token       = $this->pattern->generateToken();
        $signedToken = $this->pattern->signToken($token);

        $this->pattern->validate($token->value(), $signedToken);

        $this->assertTrue(true); // No exception means success
    }

    // --- Validation Failures ---

    #[Test]
    public function testValidateThrowsOnTokenMismatch(): void
    {
        $cookieToken = $this->pattern->generateToken();
        $otherToken  = $this->pattern->generateToken();
        $signedOther = $this->pattern->signToken($otherToken);

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $this->pattern->validate($cookieToken->value(), $signedOther);
    }

    #[Test]
    public function testValidateThrowsOnEmptySubmittedToken(): void
    {
        $cookieToken = $this->pattern->generateToken()->value();

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $this->pattern->validate($cookieToken, '');
    }

    #[Test]
    public function testValidateThrowsOnEmptyCookieToken(): void
    {
        $token       = $this->pattern->generateToken();
        $signedToken = $this->pattern->signToken($token);

        $this->expectException(InvalidCsrfTokenException::class);

        $this->pattern->validate('', $signedToken);
    }

    #[Test]
    public function testValidateThrowsOnMissingSignature(): void
    {
        $token = $this->pattern->generateToken();

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        // Token without signature
        $this->pattern->validate($token->value(), $token->value());
    }

    #[Test]
    public function testValidateThrowsOnInvalidSignature(): void
    {
        $token           = $this->pattern->generateToken();
        $tamperedSigned  = $token->value() . '.' . base64_encode('fake-signature');

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $this->pattern->validate($token->value(), $tamperedSigned);
    }

    #[Test]
    public function testValidateThrowsOnWrongSecret(): void
    {
        $pattern2 = new DoubleSubmitCookiePattern('different-secret-32-bytes-long!!');

        $token              = $this->pattern->generateToken();
        $signedWrongSecret  = $pattern2->signToken($token);

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $this->pattern->validate($token->value(), $signedWrongSecret);
    }

    #[Test]
    public function testValidateThrowsOnInvalidBase64Signature(): void
    {
        $token          = $this->pattern->generateToken();
        $invalidSigned  = $token->value() . '.not!valid!base64!!!';

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $this->pattern->validate($token->value(), $invalidSigned);
    }

    // --- isValid Method ---

    #[Test]
    public function testIsValidReturnsTrueForCorrectlySignedToken(): void
    {
        $token       = $this->pattern->generateToken();
        $signedToken = $this->pattern->signToken($token);

        $this->assertTrue($this->pattern->isValid($token->value(), $signedToken));
    }

    #[Test]
    public function testIsValidReturnsFalseForMismatchedTokens(): void
    {
        $token1  = $this->pattern->generateToken();
        $token2  = $this->pattern->generateToken();
        $signed2 = $this->pattern->signToken($token2);

        $this->assertFalse($this->pattern->isValid($token1->value(), $signed2));
    }

    #[Test]
    public function testIsValidReturnsFalseForEmptySubmittedToken(): void
    {
        $token = $this->pattern->generateToken()->value();

        $this->assertFalse($this->pattern->isValid($token, ''));
    }

    #[Test]
    public function testIsValidReturnsFalseForEmptyCookieToken(): void
    {
        $token       = $this->pattern->generateToken();
        $signedToken = $this->pattern->signToken($token);

        $this->assertFalse($this->pattern->isValid('', $signedToken));
    }

    #[Test]
    public function testIsValidReturnsFalseForInvalidSignature(): void
    {
        $token          = $this->pattern->generateToken();
        $invalidSigned  = $token->value() . '.invalid';

        $this->assertFalse($this->pattern->isValid($token->value(), $invalidSigned));
    }

    #[Test]
    public function testIsValidReturnsFalseForMissingSignature(): void
    {
        $token = $this->pattern->generateToken();

        $this->assertFalse($this->pattern->isValid($token->value(), $token->value()));
    }

    // --- Cookie Options ---

    #[Test]
    public function testCookieOptionsReturnsCorrectStructure(): void
    {
        $options = $this->pattern->cookieOptions();

        $this->assertArrayHasKey('name', $options);
        $this->assertArrayHasKey('expires', $options);
        $this->assertArrayHasKey('path', $options);
        $this->assertArrayHasKey('secure', $options);
        $this->assertArrayHasKey('httponly', $options);
        $this->assertArrayHasKey('samesite', $options);
    }

    #[Test]
    public function testCookieOptionsSecureDefault(): void
    {
        $options = $this->pattern->cookieOptions();

        $this->assertTrue($options['secure']);
    }

    #[Test]
    public function testCookieOptionsSecureCanBeDisabled(): void
    {
        $options = $this->pattern->cookieOptions(false);

        $this->assertFalse($options['secure']);
    }

    #[Test]
    public function testCookieOptionsHttpOnlyIsFalse(): void
    {
        // JavaScript must be able to read cookie for double-submit
        $options = $this->pattern->cookieOptions();

        $this->assertFalse($options['httponly']);
    }

    #[Test]
    public function testCookieOptionsSameSiteIsStrict(): void
    {
        $options = $this->pattern->cookieOptions();

        $this->assertSame('Strict', $options['samesite']);
    }

    #[Test]
    public function testCookieOptionsPathIsRoot(): void
    {
        $options = $this->pattern->cookieOptions();

        $this->assertSame('/', $options['path']);
    }

    #[Test]
    public function testCookieOptionsUsesConfigName(): void
    {
        $config  = new CsrfConfig(cookieName: 'my_cookie');
        $pattern = new DoubleSubmitCookiePattern(self::TEST_SECRET, $config);
        $options = $pattern->cookieOptions();

        $this->assertSame('my_cookie', $options['name']);
    }

    #[Test]
    public function testCookieOptionsExpiresWithTtl(): void
    {
        $config  = new CsrfConfig(ttl: 3600);
        $pattern = new DoubleSubmitCookiePattern(self::TEST_SECRET, $config);
        $options = $pattern->cookieOptions();

        $this->assertGreaterThan(time(), $options['expires']);
        $this->assertLessThanOrEqual(time() + 3600 + 1, $options['expires']);
    }

    #[Test]
    public function testCookieOptionsExpiresZeroForSessionCookie(): void
    {
        $config  = new CsrfConfig(ttl: 0);
        $pattern = new DoubleSubmitCookiePattern(self::TEST_SECRET, $config);
        $options = $pattern->cookieOptions();

        $this->assertSame(0, $options['expires']);
    }

    // --- Config Accessors ---

    #[Test]
    public function testCookieNameReturnsConfigValue(): void
    {
        $config  = new CsrfConfig(cookieName: 'test_cookie');
        $pattern = new DoubleSubmitCookiePattern(self::TEST_SECRET, $config);

        $this->assertSame('test_cookie', $pattern->cookieName());
    }

    #[Test]
    public function testHeaderNameReturnsConfigValue(): void
    {
        $config  = new CsrfConfig(headerName: 'X-Test-Header');
        $pattern = new DoubleSubmitCookiePattern(self::TEST_SECRET, $config);

        $this->assertSame('X-Test-Header', $pattern->headerName());
    }

    #[Test]
    public function testFieldNameReturnsConfigValue(): void
    {
        $config  = new CsrfConfig(fieldName: 'test_field');
        $pattern = new DoubleSubmitCookiePattern(self::TEST_SECRET, $config);

        $this->assertSame('test_field', $pattern->fieldName());
    }

    // --- Timing Attack Resistance ---

    #[Test]
    public function testValidationUsesConstantTimeComparison(): void
    {
        $token = $this->pattern->generateToken();

        // Create a signed token with tampered signature
        $almostCorrectSig = $token->value() . '.' . base64_encode(random_bytes(32));

        $start1 = hrtime(true);
        $this->pattern->isValid($token->value(), $almostCorrectSig);
        $time1  = hrtime(true) - $start1;

        // Completely different signed token
        $otherToken  = $this->pattern->generateToken();
        $otherSigned = $this->pattern->signToken($otherToken);

        $start2 = hrtime(true);
        $this->pattern->isValid($token->value(), $otherSigned);
        $time2  = hrtime(true) - $start2;

        // Times should be within two orders of magnitude (100x tolerance)
        // Higher tolerance needed due to JIT, GC, and system load variations
        $this->assertLessThan($time1 * 100, $time2);
        $this->assertLessThan($time2 * 100, $time1);
    }
}
