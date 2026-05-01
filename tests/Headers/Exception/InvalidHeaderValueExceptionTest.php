<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Headers\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Exception\InvalidHeaderValueException;

#[CoversClass(InvalidHeaderValueException::class)]
final class InvalidHeaderValueExceptionTest extends TestCase
{
    #[Test]
    public function testExtendsInvalidArgumentException(): void
    {
        $exception = InvalidHeaderValueException::containsControlCharacter('Test', 'value');

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
    }

    #[Test]
    public function testContainsControlCharacterWithLineFeed(): void
    {
        $exception = InvalidHeaderValueException::containsControlCharacter(
            'X-Custom-Header',
            "value\ninjection"
        );

        $this->assertStringContainsString('X-Custom-Header', $exception->getMessage());
        $this->assertStringContainsString('control character', $exception->getMessage());
        $this->assertStringContainsString('\\x0A', $exception->getMessage());
        $this->assertStringContainsString('header injection', $exception->getMessage());
    }

    #[Test]
    public function testContainsControlCharacterWithCarriageReturn(): void
    {
        $exception = InvalidHeaderValueException::containsControlCharacter(
            'Content-Type',
            "value\rinjection"
        );

        $this->assertStringContainsString('Content-Type', $exception->getMessage());
        $this->assertStringContainsString('\\x0D', $exception->getMessage());
    }

    #[Test]
    public function testContainsControlCharacterWithCrLf(): void
    {
        $exception = InvalidHeaderValueException::containsControlCharacter(
            'Set-Cookie',
            "value\r\nX-Injected: evil"
        );

        $this->assertStringContainsString('Set-Cookie', $exception->getMessage());
        $this->assertStringContainsString('\\x0D', $exception->getMessage());
        $this->assertStringContainsString('\\x0A', $exception->getMessage());
    }

    #[Test]
    public function testContainsControlCharacterEscapesInOutput(): void
    {
        $exception = InvalidHeaderValueException::containsControlCharacter(
            'Test',
            "line1\nline2\rline3"
        );

        // Verify the message does not contain actual control characters
        $this->assertStringNotContainsString("\n", $exception->getMessage());
        $this->assertStringNotContainsString("\r", $exception->getMessage());
    }

    #[Test]
    public function testInvalidMaxAgeWithNegativeValue(): void
    {
        $exception = InvalidHeaderValueException::invalidMaxAge(-1);

        $this->assertStringContainsString('max-age', $exception->getMessage());
        $this->assertStringContainsString('non-negative', $exception->getMessage());
        $this->assertStringContainsString('-1', $exception->getMessage());
    }

    #[Test]
    public function testInvalidMaxAgeWithLargeNegativeValue(): void
    {
        $exception = InvalidHeaderValueException::invalidMaxAge(-9999);

        $this->assertStringContainsString('-9999', $exception->getMessage());
    }

    #[Test]
    public function testPreloadRequiresIncludeSubDomains(): void
    {
        $exception = InvalidHeaderValueException::preloadRequiresIncludeSubDomains();

        $this->assertStringContainsString('preload', $exception->getMessage());
        $this->assertStringContainsString('includeSubDomains', $exception->getMessage());
    }

    #[Test]
    public function testPreloadRequiresMinMaxAge(): void
    {
        $exception = InvalidHeaderValueException::preloadRequiresMinMaxAge(31536000, 86400);

        $this->assertStringContainsString('preload', $exception->getMessage());
        $this->assertStringContainsString('max-age', $exception->getMessage());
        $this->assertStringContainsString('31536000', $exception->getMessage());
        $this->assertStringContainsString('86400', $exception->getMessage());
    }

    #[Test]
    public function testPreloadRequiresMinMaxAgeWithZero(): void
    {
        $exception = InvalidHeaderValueException::preloadRequiresMinMaxAge(31536000, 0);

        $this->assertStringContainsString('at least 31536000', $exception->getMessage());
        $this->assertStringContainsString('got: 0', $exception->getMessage());
    }

    #[Test]
    public function testInvalidPermissionAllowlist(): void
    {
        $exception = InvalidHeaderValueException::invalidPermissionAllowlist(
            'camera',
            'contains invalid origin'
        );

        $this->assertStringContainsString('camera', $exception->getMessage());
        $this->assertStringContainsString('allowlist', $exception->getMessage());
        $this->assertStringContainsString('contains invalid origin', $exception->getMessage());
    }

    #[Test]
    public function testInvalidPermissionAllowlistWithDifferentFeature(): void
    {
        $exception = InvalidHeaderValueException::invalidPermissionAllowlist(
            'geolocation',
            'newline detected'
        );

        $this->assertStringContainsString('geolocation', $exception->getMessage());
        $this->assertStringContainsString('newline detected', $exception->getMessage());
    }

    #[Test]
    public function testInvalidOrigin(): void
    {
        $exception = InvalidHeaderValueException::invalidOrigin('not-a-valid-origin');

        $this->assertStringContainsString('Invalid origin', $exception->getMessage());
        $this->assertStringContainsString('not-a-valid-origin', $exception->getMessage());
        $this->assertStringContainsString('scheme://host', $exception->getMessage());
    }

    #[Test]
    public function testInvalidOriginWithPath(): void
    {
        $exception = InvalidHeaderValueException::invalidOrigin('https://example.com/path');

        $this->assertStringContainsString('https://example.com/path', $exception->getMessage());
    }

    #[Test]
    public function testInvalidOriginWithMissingScheme(): void
    {
        $exception = InvalidHeaderValueException::invalidOrigin('example.com');

        $this->assertStringContainsString('example.com', $exception->getMessage());
    }

    #[DataProvider('headerInjectionAttemptProvider')]
    #[Test]
    public function testContainsControlCharacterDetectsInjectionAttempts(string $value, string $expectedEscaped): void
    {
        $exception = InvalidHeaderValueException::containsControlCharacter('Test-Header', $value);

        $this->assertStringContainsString($expectedEscaped, $exception->getMessage());
        $this->assertStringNotContainsString("\r", $exception->getMessage());
        $this->assertStringNotContainsString("\n", $exception->getMessage());
    }

    /**
     * @return iterable<string, array{value: string, expectedEscaped: string}>
     */
    public static function headerInjectionAttemptProvider(): iterable
    {
        yield 'LF injection' => [
            'value'           => "safe\nX-Injected: malicious",
            'expectedEscaped' => '\\x0A',
        ];

        yield 'CR injection' => [
            'value'           => "safe\rX-Injected: malicious",
            'expectedEscaped' => '\\x0D',
        ];

        yield 'CRLF injection' => [
            'value'           => "safe\r\nX-Injected: malicious",
            'expectedEscaped' => '\\x0D\\x0A',
        ];

        yield 'multiple newlines' => [
            'value'           => "line1\nline2\nline3",
            'expectedEscaped' => '\\x0A',
        ];

        yield 'mixed newlines' => [
            'value'           => "line1\r\nline2\nline3\r",
            'expectedEscaped' => '\\x0D',
        ];
    }

    #[Test]
    public function testContainsControlCharacterWithNullByte(): void
    {
        $exception = InvalidHeaderValueException::containsControlCharacter(
            'X-Test',
            "value\x00injection"
        );

        $this->assertStringContainsString('X-Test', $exception->getMessage());
        $this->assertStringContainsString('\\x00', $exception->getMessage());
        $this->assertStringContainsString('control character', $exception->getMessage());
    }

    #[Test]
    public function testContainsControlCharacterWithTab(): void
    {
        $exception = InvalidHeaderValueException::containsControlCharacter(
            'X-Test',
            "value\tinjection"
        );

        $this->assertStringContainsString('\\x09', $exception->getMessage());
    }
}
