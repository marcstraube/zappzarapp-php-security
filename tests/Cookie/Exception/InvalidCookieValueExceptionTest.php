<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Cookie\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieValueException;

#[CoversClass(InvalidCookieValueException::class)]
final class InvalidCookieValueExceptionTest extends TestCase
{
    public function testExtendsInvalidArgumentException(): void
    {
        $exception = InvalidCookieValueException::invalidCharacter('test', ';');

        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
    }

    public function testInvalidCharacter(): void
    {
        $exception = InvalidCookieValueException::invalidCharacter('value;test', ';');

        $this->assertStringContainsString('value;test', $exception->getMessage());
        $this->assertStringContainsString(';', $exception->getMessage());
    }

    public function testInvalidCharacterSemicolonShowsDescription(): void
    {
        $exception = InvalidCookieValueException::invalidCharacter('value;test', ';');

        $this->assertStringContainsString('semicolon', $exception->getMessage());
    }

    public function testInvalidCharacterCommaShowsDescription(): void
    {
        $exception = InvalidCookieValueException::invalidCharacter('value,test', ',');

        $this->assertStringContainsString('comma', $exception->getMessage());
    }

    public function testInvalidCharacterOtherCharShowsCharItself(): void
    {
        $exception = InvalidCookieValueException::invalidCharacter('value"test', '"');

        $this->assertStringContainsString('"', $exception->getMessage());
    }

    public function testInvalidCharacterTruncatesLongValue(): void
    {
        $longValue = str_repeat('a', 100);
        $exception = InvalidCookieValueException::invalidCharacter($longValue . ';more', ';');

        // Should truncate to 50 chars + ...
        $this->assertStringContainsString('...', $exception->getMessage());
        $this->assertStringContainsString(substr($longValue, 0, 50), $exception->getMessage());
    }

    public function testInvalidCharacterShortValueNotTruncated(): void
    {
        $shortValue = 'short;value';
        $exception  = InvalidCookieValueException::invalidCharacter($shortValue, ';');

        $this->assertStringContainsString($shortValue, $exception->getMessage());
        $this->assertStringNotContainsString('...', $exception->getMessage());
    }

    public function testTooLong(): void
    {
        $exception = InvalidCookieValueException::tooLong(5000, 4096);

        $this->assertStringContainsString('too long', $exception->getMessage());
        $this->assertStringContainsString('5000', $exception->getMessage());
        $this->assertStringContainsString('4096', $exception->getMessage());
        $this->assertStringContainsString('bytes', $exception->getMessage());
    }

    public function testTooLongWithExactBoundary(): void
    {
        $exception = InvalidCookieValueException::tooLong(4097, 4096);

        $this->assertStringContainsString('4097', $exception->getMessage());
        $this->assertStringContainsString('4096', $exception->getMessage());
    }

    public function testTooLongWithLargeValues(): void
    {
        $exception = InvalidCookieValueException::tooLong(1000000, 4096);

        $this->assertStringContainsString('1000000', $exception->getMessage());
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function invalidCharacterProvider(): array
    {
        return [
            'space'        => ['value test', ' '],
            'double quote' => ['value"test', '"'],
            'comma'        => ['value,test', ','],
            'semicolon'    => ['value;test', ';'],
            'backslash'    => ['value\\test', '\\'],
            'newline'      => ["value\ntest", "\n"],
            'carriage'     => ["value\rtest", "\r"],
        ];
    }

    #[DataProvider('invalidCharacterProvider')]
    public function testInvalidCharacterWithVariousChars(string $value, string $char): void
    {
        $exception = InvalidCookieValueException::invalidCharacter($value, $char);

        $this->assertInstanceOf(InvalidCookieValueException::class, $exception);
        $this->assertStringContainsString('invalid character', $exception->getMessage());
    }

    public function testAllFactoryMethodsReturnSameClass(): void
    {
        $invalid = InvalidCookieValueException::invalidCharacter('test', ';');
        $tooLong = InvalidCookieValueException::tooLong(5000, 4096);

        $this->assertInstanceOf(InvalidCookieValueException::class, $invalid);
        $this->assertInstanceOf(InvalidCookieValueException::class, $tooLong);
    }
}
