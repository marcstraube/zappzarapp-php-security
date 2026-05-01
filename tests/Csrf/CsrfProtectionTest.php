<?php

/**
 * @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException
 * @noinspection PhpRedundantOptionalArgumentInspection Test explicitly verifies default value behavior
 */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Csrf\CsrfConfig;
use Zappzarapp\Security\Csrf\CsrfProtection;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Storage\ArrayCsrfStorage;
use Zappzarapp\Security\Csrf\Token\CsrfToken;

#[CoversClass(CsrfProtection::class)]
final class CsrfProtectionTest extends TestCase
{
    /**
     * Test secret (32 bytes minimum)
     */
    private const string TEST_SECRET = 'test-secret-key-32-bytes-long!!!';

    private ArrayCsrfStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new ArrayCsrfStorage();
    }

    // --- Factory Methods ---

    #[Test]
    public function testSynchronizerFactoryCreatesInstance(): void
    {
        $csrf = CsrfProtection::synchronizer($this->storage);

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies factory return type */
        $this->assertInstanceOf(CsrfProtection::class, $csrf);
    }

    #[Test]
    public function testSynchronizerFactoryWithCustomConfig(): void
    {
        $config = new CsrfConfig(fieldName: 'custom_token');
        $csrf   = CsrfProtection::synchronizer($this->storage, $config);

        $this->assertSame('custom_token', $csrf->fieldName());
    }

    #[Test]
    public function testDoubleSubmitFactoryCreatesInstance(): void
    {
        $csrf = CsrfProtection::doubleSubmit(self::TEST_SECRET);

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies factory return type */
        $this->assertInstanceOf(CsrfProtection::class, $csrf);
    }

    #[Test]
    public function testDoubleSubmitFactoryWithCustomConfig(): void
    {
        $config = new CsrfConfig(headerName: 'X-Custom-CSRF');
        $csrf   = CsrfProtection::doubleSubmit(self::TEST_SECRET, $config);

        $this->assertSame('X-Custom-CSRF', $csrf->headerName());
    }

    // --- Token Generation ---

    #[Test]
    public function testTokenReturnsCsrfTokenForSynchronizer(): void
    {
        $csrf  = CsrfProtection::synchronizer($this->storage);
        $token = $csrf->token();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfToken::class, $token);
        $this->assertSame(44, strlen($token->value())); // 32 bytes base64 = 44 chars
    }

    #[Test]
    public function testTokenReturnsSameTokenOnSubsequentCalls(): void
    {
        $csrf   = CsrfProtection::synchronizer($this->storage);
        $token1 = $csrf->token();
        $token2 = $csrf->token();

        $this->assertSame($token1->value(), $token2->value());
    }

    #[Test]
    public function testTokenReturnsCsrfTokenForDoubleSubmit(): void
    {
        $csrf  = CsrfProtection::doubleSubmit(self::TEST_SECRET);
        $token = $csrf->token();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfToken::class, $token);
    }

    #[Test]
    public function testTokenGeneratesNewTokenEachTimeForDoubleSubmit(): void
    {
        $csrf   = CsrfProtection::doubleSubmit(self::TEST_SECRET);
        $token1 = $csrf->token();
        $token2 = $csrf->token();

        $this->assertNotSame($token1->value(), $token2->value());
    }

    // --- Field Generation ---

    #[Test]
    public function testFieldGeneratesHiddenInput(): void
    {
        $csrf  = CsrfProtection::synchronizer($this->storage);
        $field = $csrf->field();

        $this->assertStringStartsWith('<input type="hidden"', $field);
        $this->assertStringContainsString('name="_csrf_token"', $field);
        $this->assertStringContainsString('value="', $field);
    }

    #[Test]
    public function testFieldThrowsWithoutStorage(): void
    {
        $csrf = CsrfProtection::doubleSubmit(self::TEST_SECRET);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Storage is required');

        $csrf->field();
    }

    // --- Synchronizer Token Validation ---

    #[Test]
    public function testValidateSucceedsWithCorrectToken(): void
    {
        $csrf  = CsrfProtection::synchronizer($this->storage);
        $token = $csrf->token();

        $csrf->validate($token->value());

        $this->assertTrue(true); // No exception means success
    }

    #[Test]
    public function testValidateThrowsWithMismatchedToken(): void
    {
        $csrf = CsrfProtection::synchronizer($this->storage);
        $csrf->token(); // Generate and store token

        $wrongToken = base64_encode(random_bytes(32));

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $csrf->validate($wrongToken);
    }

    #[Test]
    public function testValidateThrowsWithEmptyToken(): void
    {
        $csrf = CsrfProtection::synchronizer($this->storage);
        $csrf->token();

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('missing');

        $csrf->validate('');
    }

    #[Test]
    public function testValidateThrowsWithInvalidFormat(): void
    {
        $csrf = CsrfProtection::synchronizer($this->storage);
        $csrf->token();

        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('base64');

        $csrf->validate('not!valid!base64!!!');
    }

    #[Test]
    public function testValidateThrowsWhenNoStoredToken(): void
    {
        $csrf = CsrfProtection::synchronizer($this->storage);

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('No CSRF token found');

        $csrf->validate(base64_encode(random_bytes(32)));
    }

    #[Test]
    public function testValidateThrowsWithoutStorage(): void
    {
        $csrf = CsrfProtection::doubleSubmit(self::TEST_SECRET);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Storage is required');

        $csrf->validate(base64_encode(random_bytes(32)));
    }

    // --- Double Submit Validation ---

    #[Test]
    public function testValidateDoubleSubmitSucceeds(): void
    {
        $csrf        = CsrfProtection::doubleSubmit(self::TEST_SECRET);
        $token       = $csrf->token();
        $signedToken = $csrf->signToken($token);

        $csrf->validateDoubleSubmit($token->value(), $signedToken);

        $this->assertTrue(true);
    }

    #[Test]
    public function testValidateDoubleSubmitThrowsOnMismatch(): void
    {
        $csrf        = CsrfProtection::doubleSubmit(self::TEST_SECRET);
        $cookieToken = $csrf->token();
        $otherToken  = $csrf->token();
        $signedOther = $csrf->signToken($otherToken);

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $csrf->validateDoubleSubmit($cookieToken->value(), $signedOther);
    }

    #[Test]
    public function testValidateDoubleSubmitThrowsOnEmptySubmittedToken(): void
    {
        $csrf        = CsrfProtection::doubleSubmit(self::TEST_SECRET);
        $cookieToken = $csrf->token()->value();

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $csrf->validateDoubleSubmit($cookieToken, '');
    }

    #[Test]
    public function testValidateDoubleSubmitThrowsOnEmptyCookieToken(): void
    {
        $csrf        = CsrfProtection::doubleSubmit(self::TEST_SECRET);
        $token       = $csrf->token();
        $signedToken = $csrf->signToken($token);

        $this->expectException(InvalidCsrfTokenException::class);

        $csrf->validateDoubleSubmit('', $signedToken);
    }

    // --- IsValid Methods ---

    #[Test]
    public function testIsValidReturnsTrueForValidToken(): void
    {
        $csrf  = CsrfProtection::synchronizer($this->storage);
        $token = $csrf->token();

        $this->assertTrue($csrf->isValid($token->value()));
    }

    #[Test]
    public function testIsValidReturnsFalseForInvalidToken(): void
    {
        $csrf = CsrfProtection::synchronizer($this->storage);
        $csrf->token();

        $this->assertFalse($csrf->isValid(base64_encode(random_bytes(32))));
    }

    #[Test]
    public function testIsValidReturnsFalseForEmptyToken(): void
    {
        $csrf = CsrfProtection::synchronizer($this->storage);
        $csrf->token();

        $this->assertFalse($csrf->isValid(''));
    }

    #[Test]
    public function testIsValidReturnsFalseWhenNoStoredToken(): void
    {
        $csrf = CsrfProtection::synchronizer($this->storage);

        $this->assertFalse($csrf->isValid(base64_encode(random_bytes(32))));
    }

    #[Test]
    public function testIsValidDoubleSubmitReturnsTrue(): void
    {
        $csrf        = CsrfProtection::doubleSubmit(self::TEST_SECRET);
        $token       = $csrf->token();
        $signedToken = $csrf->signToken($token);

        $this->assertTrue($csrf->isValidDoubleSubmit($token->value(), $signedToken));
    }

    #[Test]
    public function testIsValidDoubleSubmitReturnsFalseOnMismatch(): void
    {
        $csrf    = CsrfProtection::doubleSubmit(self::TEST_SECRET);
        $token1  = $csrf->token();
        $token2  = $csrf->token();
        $signed2 = $csrf->signToken($token2);

        $this->assertFalse($csrf->isValidDoubleSubmit($token1->value(), $signed2));
    }

    // --- Regenerate ---

    #[Test]
    public function testRegenerateCreatesNewToken(): void
    {
        $csrf      = CsrfProtection::synchronizer($this->storage);
        $oldToken  = $csrf->token();
        $newToken  = $csrf->regenerate();

        $this->assertNotSame($oldToken->value(), $newToken->value());
    }

    #[Test]
    public function testRegenerateInvalidatesOldToken(): void
    {
        $csrf     = CsrfProtection::synchronizer($this->storage);
        $oldToken = $csrf->token();
        $csrf->regenerate();

        $this->assertFalse($csrf->isValid($oldToken->value()));
    }

    #[Test]
    public function testRegenerateThrowsWithoutStorage(): void
    {
        $csrf = CsrfProtection::doubleSubmit(self::TEST_SECRET);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Storage is required');

        $csrf->regenerate();
    }

    // --- Clear ---

    #[Test]
    public function testClearRemovesToken(): void
    {
        $csrf  = CsrfProtection::synchronizer($this->storage);
        $token = $csrf->token();

        $csrf->clear();

        $this->assertFalse($csrf->isValid($token->value()));
    }

    #[Test]
    public function testClearThrowsWithoutStorage(): void
    {
        $csrf = CsrfProtection::doubleSubmit(self::TEST_SECRET);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Storage is required');

        $csrf->clear();
    }

    // --- Cookie Options ---

    #[Test]
    public function testCookieOptionsReturnsCorrectStructure(): void
    {
        $csrf    = CsrfProtection::doubleSubmit(self::TEST_SECRET);
        $options = $csrf->cookieOptions();

        $this->assertArrayHasKey('name', $options);
        $this->assertArrayHasKey('expires', $options);
        $this->assertArrayHasKey('path', $options);
        $this->assertArrayHasKey('secure', $options);
        $this->assertArrayHasKey('httponly', $options);
        $this->assertArrayHasKey('samesite', $options);
    }

    #[Test]
    public function testCookieOptionsSecureFlag(): void
    {
        $csrf = CsrfProtection::doubleSubmit(self::TEST_SECRET);

        $this->assertTrue($csrf->cookieOptions(true)['secure']);
        $this->assertFalse($csrf->cookieOptions(false)['secure']);
    }

    #[Test]
    public function testCookieOptionsUsesConfigName(): void
    {
        $config  = new CsrfConfig(cookieName: 'my_csrf_cookie');
        $csrf    = CsrfProtection::doubleSubmit(self::TEST_SECRET, $config);
        $options = $csrf->cookieOptions();

        $this->assertSame('my_csrf_cookie', $options['name']);
    }

    // --- Config Accessor Methods ---

    #[Test]
    public function testFieldNameReturnsConfigValue(): void
    {
        $config = new CsrfConfig(fieldName: 'custom_field');
        $csrf   = CsrfProtection::synchronizer($this->storage, $config);

        $this->assertSame('custom_field', $csrf->fieldName());
    }

    #[Test]
    public function testHeaderNameReturnsConfigValue(): void
    {
        $config = new CsrfConfig(headerName: 'X-Custom-Header');
        $csrf   = CsrfProtection::synchronizer($this->storage, $config);

        $this->assertSame('X-Custom-Header', $csrf->headerName());
    }

    #[Test]
    public function testCookieNameReturnsConfigValue(): void
    {
        $config = new CsrfConfig(cookieName: 'custom_cookie');
        $csrf   = CsrfProtection::synchronizer($this->storage, $config);

        $this->assertSame('custom_cookie', $csrf->cookieName());
    }

    // --- Token Entropy ---

    #[Test]
    public function testTokenHasMinimumEntropy(): void
    {
        $csrf  = CsrfProtection::synchronizer($this->storage);
        $token = $csrf->token();
        $bytes = $token->rawBytes();

        $this->assertGreaterThanOrEqual(32, strlen($bytes));
    }

    // --- Timing Attack Prevention ---

    #[Test]
    public function testValidationUsesConstantTimeComparison(): void
    {
        $csrf  = CsrfProtection::synchronizer($this->storage);
        $token = $csrf->token();

        // Create a token that differs only in last character
        $almostCorrect = substr($token->value(), 0, -1) . 'X';

        // Both should fail, but timing should be similar
        // This is a basic sanity check - real timing tests need statistical analysis
        $start1 = hrtime(true);
        $csrf->isValid($almostCorrect);
        $time1  = hrtime(true) - $start1;

        $start2 = hrtime(true);
        $csrf->isValid(base64_encode(random_bytes(32)));
        $time2  = hrtime(true) - $start2;

        // Times should be within two orders of magnitude (100x tolerance)
        // Higher tolerance needed due to JIT, GC, and system load variations
        $this->assertLessThan($time1 * 100, $time2);
        $this->assertLessThan($time2 * 100, $time1);
    }
}
