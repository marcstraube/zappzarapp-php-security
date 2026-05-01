<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Cookie;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Cookie\CookieOptions;
use Zappzarapp\Security\Cookie\CookieValidator;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieNameException;
use Zappzarapp\Security\Cookie\Exception\InvalidCookieValueException;
use Zappzarapp\Security\Cookie\SameSitePolicy;

#[CoversClass(CookieValidator::class)]
#[UsesClass(InvalidCookieNameException::class)]
#[UsesClass(InvalidCookieValueException::class)]
#[UsesClass(CookieOptions::class)]
#[UsesClass(SameSitePolicy::class)]
final class CookieValidatorTest extends TestCase
{
    private CookieValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new CookieValidator();
    }

    #[Test]
    public function testValidateNameAcceptsValidName(): void
    {
        $this->validator->validateName('session_id');
        $this->validator->validateName('CSRF_TOKEN');
        $this->validator->validateName('user-preference');
        $this->validator->validateName('auth123');

        $this->assertTrue(true);
    }

    #[Test]
    public function testValidateNameRejectsEmptyName(): void
    {
        $this->expectException(InvalidCookieNameException::class);
        $this->expectExceptionMessage('cannot be empty');

        $this->validator->validateName('');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidNameCharactersProvider(): array
    {
        return [
            'semicolon'    => ['cookie;name'],
            'comma'        => ['cookie,name'],
            'space'        => ['cookie name'],
            'tab'          => ["cookie\tname"],
            'newline'      => ["cookie\nname"],
            'carriage'     => ["cookie\rname"],
            'equals'       => ['cookie=name'],
            'open bracket' => ['cookie[name'],
            'close bracket'=> ['cookie]name'],
            'open brace'   => ['cookie{name'],
            'close brace'  => ['cookie}name'],
            'double quote' => ['cookie"name'],
            'backslash'    => ['cookie\\name'],
        ];
    }

    #[DataProvider('invalidNameCharactersProvider')]
    #[Test]
    public function testValidateNameRejectsInvalidCharacters(string $name): void
    {
        $this->expectException(InvalidCookieNameException::class);

        $this->validator->validateName($name);
    }

    #[Test]
    public function testValidateValueAcceptsValidValue(): void
    {
        $this->validator->validateValue('abc123');
        $this->validator->validateValue('base64+encoded/value==');
        $this->validator->validateValue('');

        $this->assertTrue(true);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidValueCharactersProvider(): array
    {
        return [
            'semicolon' => ['value;injection'],
            'newline'   => ["value\ninjection"],
            'carriage'  => ["value\rinjection"],
        ];
    }

    #[DataProvider('invalidValueCharactersProvider')]
    #[Test]
    public function testValidateValueRejectsInvalidCharacters(string $value): void
    {
        $this->expectException(InvalidCookieValueException::class);

        $this->validator->validateValue($value);
    }

    #[Test]
    public function testIsValidNameReturnsTrue(): void
    {
        $this->assertTrue($this->validator->isValidName('session'));
        $this->assertTrue($this->validator->isValidName('CSRF_TOKEN'));
    }

    #[Test]
    public function testIsValidNameReturnsFalse(): void
    {
        $this->assertFalse($this->validator->isValidName(''));
        $this->assertFalse($this->validator->isValidName('name;'));
        $this->assertFalse($this->validator->isValidName("name\n"));
    }

    #[Test]
    public function testIsValidValueReturnsTrue(): void
    {
        $this->assertTrue($this->validator->isValidValue('value'));
        $this->assertTrue($this->validator->isValidValue(''));
    }

    #[Test]
    public function testIsValidValueReturnsFalse(): void
    {
        $this->assertFalse($this->validator->isValidValue('value;'));
        $this->assertFalse($this->validator->isValidValue("value\n"));
    }

    // --- Cookie Prefix Validation ---

    #[Test]
    public function testValidatePrefixConstraintsPassesForHostPrefix(): void
    {
        $options = new CookieOptions(
            path: '/',
            domain: '',
            secure: true
        );

        $this->validator->validatePrefixConstraints('__Host-session', $options);

        $this->assertTrue(true); // No exception means success
    }

    #[Test]
    public function testValidatePrefixConstraintsPassesForSecurePrefix(): void
    {
        $options = new CookieOptions(
            secure: true
        );

        $this->validator->validatePrefixConstraints('__Secure-token', $options);

        $this->assertTrue(true);
    }

    #[Test]
    public function testValidatePrefixConstraintsPassesForNonPrefixedCookie(): void
    {
        // Non-prefixed cookies have no constraints
        $options = new CookieOptions(
            path: '/admin',
            domain: 'example.com',
            secure: false
        );

        $this->validator->validatePrefixConstraints('regular_cookie', $options);

        $this->assertTrue(true);
    }

    #[Test]
    public function testHostPrefixRequiresSecureFlag(): void
    {
        $options = new CookieOptions(
            path: '/',
            domain: '',
            secure: false
        );

        $this->expectException(InvalidCookieNameException::class);
        $this->expectExceptionMessage('Secure flag must be true');

        $this->validator->validatePrefixConstraints('__Host-session', $options);
    }

    #[Test]
    public function testHostPrefixRequiresRootPath(): void
    {
        $options = new CookieOptions(
            path: '/admin',
            domain: '',
            secure: true
        );

        $this->expectException(InvalidCookieNameException::class);
        $this->expectExceptionMessage('Path must be "/"');

        $this->validator->validatePrefixConstraints('__Host-session', $options);
    }

    #[Test]
    public function testHostPrefixRequiresEmptyDomain(): void
    {
        $options = new CookieOptions(
            path: '/',
            domain: 'example.com',
            secure: true
        );

        $this->expectException(InvalidCookieNameException::class);
        $this->expectExceptionMessage('Domain must be empty');

        $this->validator->validatePrefixConstraints('__Host-session', $options);
    }

    #[Test]
    public function testSecurePrefixRequiresSecureFlag(): void
    {
        $options = new CookieOptions(
            secure: false
        );

        $this->expectException(InvalidCookieNameException::class);
        $this->expectExceptionMessage('Secure flag must be true');

        $this->validator->validatePrefixConstraints('__Secure-token', $options);
    }

    #[Test]
    public function testSecurePrefixAllowsCustomPathAndDomain(): void
    {
        // __Secure- only requires Secure flag, path and domain are flexible
        $options = new CookieOptions(
            path: '/admin',
            domain: 'example.com',
            secure: true
        );

        $this->validator->validatePrefixConstraints('__Secure-token', $options);

        $this->assertTrue(true);
    }

    #[Test]
    public function testHasPrefixDetectsHostPrefix(): void
    {
        $this->assertTrue($this->validator->hasPrefix('__Host-session'));
    }

    #[Test]
    public function testHasPrefixDetectsSecurePrefix(): void
    {
        $this->assertTrue($this->validator->hasPrefix('__Secure-token'));
    }

    #[Test]
    public function testHasPrefixReturnsFalseForNonPrefixed(): void
    {
        $this->assertFalse($this->validator->hasPrefix('session'));
        $this->assertFalse($this->validator->hasPrefix('_Host-session')); // Single underscore
        $this->assertFalse($this->validator->hasPrefix('Host-session'));
    }

    #[Test]
    public function testIsValidPrefixConstraintsReturnsTrue(): void
    {
        $options = new CookieOptions(path: '/', domain: '', secure: true);

        $this->assertTrue($this->validator->isValidPrefixConstraints('__Host-session', $options));
    }

    #[Test]
    public function testIsValidPrefixConstraintsReturnsFalse(): void
    {
        $options = new CookieOptions(secure: false);

        $this->assertFalse($this->validator->isValidPrefixConstraints('__Host-session', $options));
        $this->assertFalse($this->validator->isValidPrefixConstraints('__Secure-token', $options));
    }
}
