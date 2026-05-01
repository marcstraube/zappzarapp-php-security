<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Cookie\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieNameException;

#[CoversClass(InvalidCookieNameException::class)]
final class InvalidCookieNameExceptionTest extends TestCase
{
    #[Test]
    public function testExtendsInvalidArgumentException(): void
    {
        $exception = InvalidCookieNameException::emptyName();

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies type inheritance */
        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
    }

    #[Test]
    public function testEmptyName(): void
    {
        $exception = InvalidCookieNameException::emptyName();

        $this->assertStringContainsString('cannot be empty', $exception->getMessage());
    }

    #[Test]
    public function testInvalidCharacter(): void
    {
        $exception = InvalidCookieNameException::invalidCharacter('test;name', ';');

        $this->assertStringContainsString('test;name', $exception->getMessage());
        $this->assertStringContainsString(';', $exception->getMessage());
    }

    #[Test]
    public function testInvalidCharacterWithSpace(): void
    {
        $exception = InvalidCookieNameException::invalidCharacter('test name', ' ');

        $this->assertStringContainsString('test name', $exception->getMessage());
        $this->assertStringContainsString('(space)', $exception->getMessage());
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function invalidCharacterProvider(): array
    {
        return [
            'semicolon'     => ['name;value', ';'],
            'comma'         => ['name,value', ','],
            'equals'        => ['name=value', '='],
            'tab'           => ["name\tvalue", "\t"],
            'newline'       => ["name\nvalue", "\n"],
            'carriage'      => ["name\rvalue", "\r"],
            'open paren'    => ['name(value', '('],
            'close paren'   => ['name)value', ')'],
            'less than'     => ['name<value', '<'],
            'greater than'  => ['name>value', '>'],
            'at sign'       => ['name@value', '@'],
            'colon'         => ['name:value', ':'],
            'backslash'     => ['name\\value', '\\'],
            'double quote'  => ['name"value', '"'],
            'forward slash' => ['name/value', '/'],
            'open bracket'  => ['name[value', '['],
            'close bracket' => ['name]value', ']'],
            'question mark' => ['name?value', '?'],
            'open brace'    => ['name{value', '{'],
            'close brace'   => ['name}value', '}'],
        ];
    }

    #[DataProvider('invalidCharacterProvider')]
    #[Test]
    public function testInvalidCharacterWithVariousChars(string $name, string $char): void
    {
        $exception = InvalidCookieNameException::invalidCharacter($name, $char);

        $this->assertStringContainsString($name, $exception->getMessage());
    }

    #[Test]
    public function testAllFactoryMethodsReturnSameClass(): void
    {
        $empty   = InvalidCookieNameException::emptyName();
        $invalid = InvalidCookieNameException::invalidCharacter('test', ';');

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies factory return types */
        $this->assertInstanceOf(InvalidCookieNameException::class, $empty);
        /** @noinspection PhpConditionAlreadyCheckedInspection */
        $this->assertInstanceOf(InvalidCookieNameException::class, $invalid);
    }
}
