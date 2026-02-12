<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Sql;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Sql\SqlEscaper;

#[CoversClass(SqlEscaper::class)]
final class SqlEscaperTest extends TestCase
{
    private SqlEscaper $escaper;

    protected function setUp(): void
    {
        $this->escaper = new SqlEscaper();
    }

    public function testEscapeLikeEscapesPercent(): void
    {
        $this->assertSame('50\\%', $this->escaper->escapeLike('50%'));
    }

    public function testEscapeLikeEscapesUnderscore(): void
    {
        $this->assertSame('test\\_value', $this->escaper->escapeLike('test_value'));
    }

    public function testEscapeLikeEscapesBackslash(): void
    {
        $this->assertSame('path\\\\to\\\\file', $this->escaper->escapeLike('path\\to\\file'));
    }

    public function testEscapeLikeEscapesMultipleSpecialChars(): void
    {
        $this->assertSame('100\\% of\\_users', $this->escaper->escapeLike('100% of_users'));
    }

    public function testEscapeLikeWithCustomEscapeChar(): void
    {
        $this->assertSame('50!%', $this->escaper->escapeLike('50%', '!'));
    }

    public function testEscapeLikeWithEmptyString(): void
    {
        $this->assertSame('', $this->escaper->escapeLike(''));
    }

    #[DataProvider('validIdentifierProvider')]
    public function testIsValidIdentifierReturnsTrueForValidIdentifiers(string $identifier): void
    {
        $this->assertTrue($this->escaper->isValidIdentifier($identifier));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function validIdentifierProvider(): iterable
    {
        yield 'simple name' => ['name'];
        yield 'with underscore' => ['user_name'];
        yield 'starts with underscore' => ['_private'];
        yield 'uppercase' => ['TABLE_NAME'];
        yield 'mixed case' => ['userName'];
        yield 'with numbers' => ['user123'];
        yield 'single letter' => ['a'];
        yield 'single underscore' => ['_'];
    }

    #[DataProvider('invalidIdentifierProvider')]
    public function testIsValidIdentifierReturnsFalseForInvalidIdentifiers(string $identifier): void
    {
        $this->assertFalse($this->escaper->isValidIdentifier($identifier));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function invalidIdentifierProvider(): iterable
    {
        yield 'starts with number' => ['123invalid'];
        yield 'contains space' => ['user name'];
        yield 'contains dash' => ['user-name'];
        yield 'contains dot' => ['user.name'];
        yield 'empty string' => [''];
        yield 'sql injection attempt' => ['name; DROP TABLE'];
        yield 'contains quotes' => ["user'name"];
        yield 'contains backtick' => ['user`name'];
    }

    public function testValidateIdentifierReturnsIdentifierWhenInAllowedList(): void
    {
        $result = $this->escaper->validateIdentifier('name', ['name', 'email', 'id']);

        $this->assertSame('name', $result);
    }

    public function testValidateIdentifierThrowsWhenNotInAllowedList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid identifier "password"');

        $this->escaper->validateIdentifier('password', ['name', 'email', 'id']);
    }

    public function testValidateIdentifierThrowsWithEmptyAllowedList(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->escaper->validateIdentifier('name', []);
    }

    public function testValidateIdentifierIsCaseSensitive(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->escaper->validateIdentifier('Name', ['name', 'email']);
    }

    public function testValidateIdentifierShowsAllowedInErrorMessage(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Allowed: name, email, id');

        $this->escaper->validateIdentifier('invalid', ['name', 'email', 'id']);
    }
}
