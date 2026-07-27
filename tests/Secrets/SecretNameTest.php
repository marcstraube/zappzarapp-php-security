<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Secrets\Exception\InvalidSecretNameException;
use Zappzarapp\Security\Secrets\SecretName;

#[CoversClass(SecretName::class)]
#[CoversClass(InvalidSecretNameException::class)]
final class SecretNameTest extends TestCase
{
    #[Test]
    public function testAcceptsValidName(): void
    {
        $name = new SecretName('db_password');

        $this->assertSame('db_password', $name->value);
    }

    #[DataProvider('validNameProvider')]
    #[Test]
    public function testAcceptsValidNames(string $value): void
    {
        $name = SecretName::fromString($value);

        $this->assertSame($value, $name->value);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validNameProvider(): array
    {
        return [
            'single letter'        => ['a'],
            'single digit'         => ['0'],
            'digit first'          => ['0secret'],
            'uppercase'            => ['DB_PASSWORD'],
            'dots'                 => ['app.db.password'],
            'hyphens'              => ['api-key'],
            'mixed'                => ['App.db-password_v2'],
            'inner double dots'    => ['a..b'],
            'maximum length'       => [str_repeat('a', 255)],
        ];
    }

    #[Test]
    public function testRejectsEmptyName(): void
    {
        $this->expectException(InvalidSecretNameException::class);
        $this->expectExceptionMessage('Secret name must not be empty');

        new SecretName('');
    }

    #[Test]
    public function testRejectsTooLongName(): void
    {
        $this->expectException(InvalidSecretNameException::class);
        $this->expectExceptionMessage('Secret name must not exceed 255 characters');

        new SecretName(str_repeat('a', 256));
    }

    #[DataProvider('invalidNameProvider')]
    #[Test]
    public function testRejectsInvalidNames(string $value): void
    {
        $this->expectException(InvalidSecretNameException::class);
        $this->expectExceptionMessage('Secret name contains invalid characters');

        new SecretName($value);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidNameProvider(): array
    {
        return [
            'hidden file'          => ['.hidden'],
            'current directory'    => ['.'],
            'parent directory'     => ['..'],
            'forward slash'        => ['a/b'],
            'backslash'            => ['a\\b'],
            'leading hyphen'       => ['-name'],
            'leading underscore'   => ['_name'],
            'newline'              => ["a\nb"],
            'trailing newline'     => ["ab\n"],
            'carriage return'      => ["a\rb"],
            'null byte'            => ["a\0b"],
            'space'                => ['a b'],
            'semicolon'            => ['a;b'],
            'non-ascii'            => ['pässword'],
            'equals sign'          => ['a=b'],
        ];
    }

    #[Test]
    public function testMaxLengthConstant(): void
    {
        $this->assertSame(255, SecretName::MAX_LENGTH);
    }

    #[DataProvider('envVariableNameProvider')]
    #[Test]
    public function testToEnvVariableName(string $name, string $prefix, string $expected): void
    {
        $this->assertSame($expected, (new SecretName($name))->toEnvVariableName($prefix));
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function envVariableNameProvider(): array
    {
        return [
            'lowercase'            => ['db_password', '', 'DB_PASSWORD'],
            'dots to underscores'  => ['app.db.password', '', 'APP_DB_PASSWORD'],
            'hyphens'              => ['api-key', '', 'API_KEY'],
            'mixed case'           => ['Db.Pass-word_x', '', 'DB_PASS_WORD_X'],
            'with prefix'          => ['db_password', 'APP_', 'APP_DB_PASSWORD'],
            'already uppercase'    => ['DB_PASSWORD', '', 'DB_PASSWORD'],
        ];
    }
}
