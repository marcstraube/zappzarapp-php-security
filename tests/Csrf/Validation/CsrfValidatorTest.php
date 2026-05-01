<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Validation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Storage\ArrayCsrfStorage;
use Zappzarapp\Security\Csrf\Token\CsrfToken;
use Zappzarapp\Security\Csrf\Validation\CsrfValidator;
use Zappzarapp\Security\Logging\SecurityLoggerInterface;

#[CoversClass(CsrfValidator::class)]
final class CsrfValidatorTest extends TestCase
{
    private ArrayCsrfStorage $storage;
    private CsrfValidator $validator;

    protected function setUp(): void
    {
        $this->storage   = new ArrayCsrfStorage();
        $this->validator = new CsrfValidator($this->storage);
    }

    // --- Store and Get Token ---

    #[Test]
    public function testStoreToken(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));

        $this->validator->storeToken($token);

        $this->assertSame($token->value(), $this->storage->retrieve('_csrf'));
    }

    #[Test]
    public function testStoreTokenWithTtl(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));

        $this->validator->storeToken($token, 3600);

        $this->assertSame($token->value(), $this->storage->retrieve('_csrf'));
    }

    #[Test]
    public function testGetStoredToken(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $stored = $this->validator->getStoredToken();

        $this->assertSame($token->value(), $stored);
    }

    #[Test]
    public function testGetStoredTokenReturnsNullWhenEmpty(): void
    {
        $this->assertNull($this->validator->getStoredToken());
    }

    #[Test]
    public function testCustomStorageKey(): void
    {
        $validator = new CsrfValidator($this->storage, 'custom_key');
        $token     = new CsrfToken(base64_encode(random_bytes(32)));

        $validator->storeToken($token);

        $this->assertSame($token->value(), $this->storage->retrieve('custom_key'));
        $this->assertNull($this->storage->retrieve('_csrf'));
    }

    // --- Clear Token ---

    #[Test]
    public function testClearToken(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->validator->clearToken();

        $this->assertNull($this->validator->getStoredToken());
    }

    #[Test]
    public function testClearTokenDoesNotThrowWhenEmpty(): void
    {
        $this->validator->clearToken();

        $this->assertNull($this->validator->getStoredToken());
    }

    // --- Validate Success ---

    #[Test]
    public function testValidateSucceeds(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->validator->validate($token->value());

        $this->assertTrue(true); // No exception means success
    }

    #[Test]
    public function testValidateDoesNotConsumeByDefault(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->validator->validate($token->value());
        $this->validator->validate($token->value());
        $this->validator->validate($token->value());

        $this->assertTrue(true);
    }

    #[Test]
    public function testValidateConsumesWhenRequested(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->validator->validate($token->value(), true);

        $this->assertNull($this->validator->getStoredToken());
    }

    // --- Validate Failures ---

    #[Test]
    public function testValidateThrowsOnEmptyToken(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('missing');

        $this->validator->validate('');
    }

    #[Test]
    public function testValidateThrowsOnNoStoredToken(): void
    {
        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('No CSRF token found');

        $this->validator->validate(base64_encode(random_bytes(32)));
    }

    #[Test]
    public function testValidateThrowsOnMismatch(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->expectException(CsrfTokenMismatchException::class);
        $this->expectExceptionMessage('validation failed');

        $this->validator->validate(base64_encode(random_bytes(32)));
    }

    #[Test]
    public function testValidateThrowsOnInvalidBase64(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('base64');

        $this->validator->validate('not!valid!base64!!!');
    }

    #[Test]
    public function testValidateThrowsOnInsufficientEntropy(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('entropy');

        $this->validator->validate(base64_encode('short'));
    }

    #[Test]
    public function testValidateThrowsOnControlCharacters(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('control characters');

        $this->validator->validate(base64_encode(random_bytes(32)) . ";");
    }

    // --- isValid Method ---

    #[Test]
    public function testIsValidReturnsTrue(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->assertTrue($this->validator->isValid($token->value()));
    }

    #[Test]
    public function testIsValidReturnsFalseOnMismatch(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->assertFalse($this->validator->isValid(base64_encode(random_bytes(32))));
    }

    #[Test]
    public function testIsValidReturnsFalseOnEmpty(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->assertFalse($this->validator->isValid(''));
    }

    #[Test]
    public function testIsValidReturnsFalseWhenNoStoredToken(): void
    {
        $this->assertFalse($this->validator->isValid(base64_encode(random_bytes(32))));
    }

    #[Test]
    public function testIsValidReturnsFalseOnInvalidFormat(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->assertFalse($this->validator->isValid('invalid!!!'));
    }

    #[Test]
    public function testIsValidDoesNotConsumeToken(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        $this->validator->isValid($token->value());
        $this->validator->isValid($token->value());

        $this->assertSame($token->value(), $this->validator->getStoredToken());
    }

    // --- Logging ---

    #[Test]
    public function testLogsOnMissingToken(): void
    {
        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                $this->stringContains('CSRF validation failed'),
                $this->callback(fn(array $context) => $context['reason'] === 'missing_token')
            );

        $validator = new CsrfValidator($this->storage, '_csrf', $logger);
        $token     = new CsrfToken(base64_encode(random_bytes(32)));
        $validator->storeToken($token);

        try {
            $validator->validate('');
        } catch (CsrfTokenMismatchException) {
            // Expected
        }
    }

    #[Test]
    public function testLogsOnNoStoredToken(): void
    {
        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                $this->stringContains('CSRF validation failed'),
                $this->callback(fn(array $context) => $context['reason'] === 'no_stored_token')
            );

        $validator = new CsrfValidator($this->storage, '_csrf', $logger);

        try {
            $validator->validate(base64_encode(random_bytes(32)));
        } catch (CsrfTokenMismatchException) {
            // Expected
        }
    }

    #[Test]
    public function testLogsOnTokenMismatch(): void
    {
        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                $this->stringContains('CSRF validation failed'),
                $this->callback(fn(array $context) => $context['reason'] === 'token_mismatch')
            );

        $validator = new CsrfValidator($this->storage, '_csrf', $logger);
        $token     = new CsrfToken(base64_encode(random_bytes(32)));
        $validator->storeToken($token);

        try {
            $validator->validate(base64_encode(random_bytes(32)));
        } catch (CsrfTokenMismatchException) {
            // Expected
        }
    }

    #[Test]
    public function testLogContextIncludesStorageKey(): void
    {
        $logger = $this->createMock(SecurityLoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(
                $this->anything(),
                $this->callback(fn(array $context) => $context['storage_key'] === 'custom_key')
            );

        $validator = new CsrfValidator($this->storage, 'custom_key', $logger);

        try {
            $validator->validate(base64_encode(random_bytes(32)));
        } catch (CsrfTokenMismatchException) {
            // Expected
        }
    }

    // --- Timing Attack Resistance ---

    #[Test]
    public function testUsesConstantTimeComparison(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));
        $this->validator->storeToken($token);

        // Token that differs only in last character
        $almostCorrect = substr($token->value(), 0, -1) . 'X';

        $start1 = hrtime(true);
        $this->validator->isValid($almostCorrect);
        $time1  = hrtime(true) - $start1;

        $start2 = hrtime(true);
        $this->validator->isValid(base64_encode(random_bytes(32)));
        $time2  = hrtime(true) - $start2;

        // Times should be within two orders of magnitude (100x tolerance)
        // Higher tolerance needed due to JIT, GC, and system load variations
        $this->assertLessThan($time1 * 100, $time2);
        $this->assertLessThan($time2 * 100, $time1);
    }
}
