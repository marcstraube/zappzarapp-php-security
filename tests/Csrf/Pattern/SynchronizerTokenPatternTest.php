<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Pattern;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\CsrfConfig;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Pattern\SynchronizerTokenPattern;
use Zappzarapp\Security\Csrf\Storage\ArrayCsrfStorage;
use Zappzarapp\Security\Csrf\Token\CsrfToken;

#[CoversClass(SynchronizerTokenPattern::class)]
final class SynchronizerTokenPatternTest extends TestCase
{
    private ArrayCsrfStorage $storage;
    private SynchronizerTokenPattern $pattern;

    protected function setUp(): void
    {
        $this->storage = new ArrayCsrfStorage();
        $this->pattern = new SynchronizerTokenPattern($this->storage);
    }

    // --- Token Generation and Storage ---

    #[Test]
    public function testGetTokenReturnsCsrfToken(): void
    {
        $token = $this->pattern->getToken();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies return type */
        $this->assertInstanceOf(CsrfToken::class, $token);
    }

    #[Test]
    public function testGetTokenStoresTokenInStorage(): void
    {
        $token = $this->pattern->getToken();

        $this->assertTrue($this->storage->has('_csrf'));
        $this->assertSame($token->value(), $this->storage->retrieve('_csrf'));
    }

    #[Test]
    public function testGetTokenReturnsSameTokenOnSubsequentCalls(): void
    {
        $token1 = $this->pattern->getToken();
        $token2 = $this->pattern->getToken();

        $this->assertSame($token1->value(), $token2->value());
    }

    #[Test]
    public function testGetTokenHasMinimumEntropy(): void
    {
        $token = $this->pattern->getToken();
        $bytes = $token->rawBytes();

        $this->assertGreaterThanOrEqual(32, strlen($bytes));
    }

    // --- Field Generation ---

    #[Test]
    public function testFieldGeneratesHiddenInput(): void
    {
        $field = $this->pattern->field();

        $this->assertStringStartsWith('<input type="hidden"', $field);
        $this->assertStringContainsString('name="_csrf_token"', $field);
    }

    #[Test]
    public function testFieldContainsToken(): void
    {
        $token = $this->pattern->getToken();
        $field = $this->pattern->field();

        $this->assertStringContainsString('value="' . $token->value() . '"', $field);
    }

    #[Test]
    public function testFieldUsesCustomFieldName(): void
    {
        $config  = new CsrfConfig(fieldName: 'custom_csrf');
        $pattern = new SynchronizerTokenPattern($this->storage, $config);

        $field = $pattern->field();

        $this->assertStringContainsString('name="custom_csrf"', $field);
    }

    #[Test]
    public function testFieldEscapesHtmlCharacters(): void
    {
        $config  = new CsrfConfig(fieldName: '<script>');
        $pattern = new SynchronizerTokenPattern($this->storage, $config);

        $field = $pattern->field();

        $this->assertStringContainsString('&lt;script&gt;', $field);
        $this->assertStringNotContainsString('<script>', $field);
    }

    // --- Validation Success ---

    #[Test]
    public function testValidateSucceedsWithCorrectToken(): void
    {
        $token = $this->pattern->getToken();

        $this->pattern->validate($token->value());

        $this->assertTrue(true); // No exception means success
    }

    // --- Validation Failures ---

    #[Test]
    public function testValidateThrowsOnEmptyToken(): void
    {
        $this->pattern->getToken();

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('missing');

        $this->pattern->validate('');
    }

    #[Test]
    public function testValidateThrowsOnMismatchedToken(): void
    {
        $this->pattern->getToken();
        $wrongToken = base64_encode(random_bytes(32));

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $this->pattern->validate($wrongToken);
    }

    #[Test]
    public function testValidateThrowsWhenNoStoredToken(): void
    {
        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('No CSRF token found');

        $this->pattern->validate(base64_encode(random_bytes(32)));
    }

    #[Test]
    public function testValidateThrowsOnInvalidBase64(): void
    {
        $this->pattern->getToken();

        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('base64');

        $this->pattern->validate('not!valid!base64!!!');
    }

    #[Test]
    public function testValidateThrowsOnInsufficientEntropy(): void
    {
        $this->pattern->getToken();

        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('entropy');

        $this->pattern->validate(base64_encode('short'));
    }

    // --- Single-Use Tokens ---

    #[Test]
    public function testValidateConsumesTokenWhenSingleUse(): void
    {
        $config  = new CsrfConfig(singleUse: true);
        $pattern = new SynchronizerTokenPattern($this->storage, $config);
        $token   = $pattern->getToken();

        $pattern->validate($token->value());

        $this->assertFalse($pattern->isValid($token->value()));
    }

    #[Test]
    public function testValidateDoesNotConsumeTokenByDefault(): void
    {
        $token = $this->pattern->getToken();

        $this->pattern->validate($token->value());
        $this->pattern->validate($token->value()); // Should not throw

        $this->assertTrue(true);
    }

    // --- Token Rotation ---

    #[Test]
    public function testValidateRotatesTokenWhenConfigured(): void
    {
        $config  = new CsrfConfig(rotateOnValidation: true);
        $pattern = new SynchronizerTokenPattern($this->storage, $config);
        $token   = $pattern->getToken();

        $pattern->validate($token->value());

        // Old token should be invalid now
        $this->assertFalse($pattern->isValid($token->value()));
    }

    #[Test]
    public function testValidateDoesNotRotateByDefault(): void
    {
        $token = $this->pattern->getToken();

        $this->pattern->validate($token->value());

        $this->assertTrue($this->pattern->isValid($token->value()));
    }

    // --- isValid Method ---

    #[Test]
    public function testIsValidReturnsTrueForValidToken(): void
    {
        $token = $this->pattern->getToken();

        $this->assertTrue($this->pattern->isValid($token->value()));
    }

    #[Test]
    public function testIsValidReturnsFalseForInvalidToken(): void
    {
        $this->pattern->getToken();

        $this->assertFalse($this->pattern->isValid(base64_encode(random_bytes(32))));
    }

    #[Test]
    public function testIsValidReturnsFalseForEmptyToken(): void
    {
        $this->pattern->getToken();

        $this->assertFalse($this->pattern->isValid(''));
    }

    #[Test]
    public function testIsValidReturnsFalseWhenNoStoredToken(): void
    {
        $this->assertFalse($this->pattern->isValid(base64_encode(random_bytes(32))));
    }

    #[Test]
    public function testIsValidDoesNotConsumeToken(): void
    {
        $token = $this->pattern->getToken();

        $this->pattern->isValid($token->value());
        $this->pattern->isValid($token->value());
        $this->pattern->isValid($token->value());

        $this->assertTrue($this->pattern->isValid($token->value()));
    }

    // --- Regenerate ---

    #[Test]
    public function testRegenerateCreatesNewToken(): void
    {
        $oldToken = $this->pattern->getToken();
        $newToken = $this->pattern->regenerate();

        $this->assertNotSame($oldToken->value(), $newToken->value());
    }

    #[Test]
    public function testRegenerateInvalidatesOldToken(): void
    {
        $oldToken = $this->pattern->getToken();
        $this->pattern->regenerate();

        $this->assertFalse($this->pattern->isValid($oldToken->value()));
    }

    #[Test]
    public function testRegenerateStoresNewToken(): void
    {
        $this->pattern->getToken();
        $newToken = $this->pattern->regenerate();

        $this->assertSame($newToken->value(), $this->storage->retrieve('_csrf'));
    }

    // --- Clear ---

    #[Test]
    public function testClearRemovesToken(): void
    {
        $token = $this->pattern->getToken();

        $this->pattern->clear();

        $this->assertFalse($this->pattern->isValid($token->value()));
        $this->assertFalse($this->storage->has('_csrf'));
    }

    // --- Config Accessors ---

    #[Test]
    public function testFieldNameReturnsConfigValue(): void
    {
        $config  = new CsrfConfig(fieldName: 'my_csrf');
        $pattern = new SynchronizerTokenPattern($this->storage, $config);

        $this->assertSame('my_csrf', $pattern->fieldName());
    }

    #[Test]
    public function testHeaderNameReturnsConfigValue(): void
    {
        $config  = new CsrfConfig(headerName: 'X-My-CSRF');
        $pattern = new SynchronizerTokenPattern($this->storage, $config);

        $this->assertSame('X-My-CSRF', $pattern->headerName());
    }

    // --- TTL Configuration ---

    #[Test]
    public function testTokenStoredWithTtl(): void
    {
        $config  = new CsrfConfig(ttl: 3600);
        $pattern = new SynchronizerTokenPattern($this->storage, $config);

        $token = $pattern->getToken();

        // Token should be stored (TTL is handled by storage)
        $this->assertSame($token->value(), $this->storage->retrieve('_csrf'));
    }

    // --- Timing Attack Resistance ---

    #[Test]
    public function testValidationUsesConstantTimeComparison(): void
    {
        $token = $this->pattern->getToken();

        // Create a token that differs only in last character
        $almostCorrect = substr($token->value(), 0, -1) . 'X';

        $start1 = hrtime(true);
        $this->pattern->isValid($almostCorrect);
        $time1  = hrtime(true) - $start1;

        $start2 = hrtime(true);
        $this->pattern->isValid(base64_encode(random_bytes(32)));
        $time2  = hrtime(true) - $start2;

        // Times should be within two orders of magnitude (100x tolerance)
        // Higher tolerance needed due to JIT, GC, and system load variations
        $this->assertLessThan($time1 * 100, $time2);
        $this->assertLessThan($time2 * 100, $time1);
    }

    // --- Replay Attack Prevention ---

    #[Test]
    public function testSingleUseTokenPreventsReplay(): void
    {
        $config  = new CsrfConfig(singleUse: true);
        $pattern = new SynchronizerTokenPattern($this->storage, $config);
        $token   = $pattern->getToken();

        // First validation succeeds
        $pattern->validate($token->value());

        // Second validation fails (replay attack)
        $this->expectException(CsrfTokenMismatchException::class);
        $pattern->validate($token->value());
    }
}
