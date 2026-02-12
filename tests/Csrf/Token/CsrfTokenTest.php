<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Token;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Token\CsrfToken;

#[CoversClass(CsrfToken::class)]
final class CsrfTokenTest extends TestCase
{
    public function testConstructorWithValidToken(): void
    {
        $value = base64_encode(random_bytes(32));
        $token = new CsrfToken($value);

        $this->assertSame($value, $token->value());
    }

    public function testConstructorRejectsEmptyToken(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('empty');

        new CsrfToken('');
    }

    public function testConstructorRejectsSemicolon(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('control characters');

        new CsrfToken('valid' . base64_encode(random_bytes(32)) . ';injection');
    }

    public function testConstructorRejectsNewline(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('control characters');

        new CsrfToken("valid\ninjection");
    }

    public function testConstructorRejectsCarriageReturn(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('control characters');

        new CsrfToken("valid\rinjection");
    }

    public function testConstructorRejectsInvalidBase64(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('base64');

        new CsrfToken('not!valid!base64!!!');
    }

    public function testConstructorRejectsShortToken(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('entropy');

        new CsrfToken(base64_encode('short'));
    }

    public function testValue(): void
    {
        $value = base64_encode(random_bytes(32));
        $token = new CsrfToken($value);

        $this->assertSame($value, $token->value());
    }

    public function testRawBytes(): void
    {
        $bytes = random_bytes(32);
        $value = base64_encode($bytes);
        $token = new CsrfToken($value);

        $this->assertSame($bytes, $token->rawBytes());
    }

    public function testToString(): void
    {
        $value = base64_encode(random_bytes(32));
        $token = new CsrfToken($value);

        $this->assertSame($value, (string) $token);
    }

    public function testEquals(): void
    {
        $value  = base64_encode(random_bytes(32));
        $token1 = new CsrfToken($value);
        $token2 = new CsrfToken($value);

        $this->assertTrue($token1->equals($token2));
    }

    public function testEqualsReturnsFalseForDifferentTokens(): void
    {
        $token1 = new CsrfToken(base64_encode(random_bytes(32)));
        $token2 = new CsrfToken(base64_encode(random_bytes(32)));

        $this->assertFalse($token1->equals($token2));
    }

    public function testEqualsString(): void
    {
        $value = base64_encode(random_bytes(32));
        $token = new CsrfToken($value);

        $this->assertTrue($token->equalsString($value));
    }

    public function testEqualsStringReturnsFalse(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));

        $this->assertFalse($token->equalsString(base64_encode(random_bytes(32))));
    }

    public function testMinBytesConstant(): void
    {
        $this->assertSame(32, CsrfToken::MIN_BYTES);
    }

    public function testMinimumEntropyAccepted(): void
    {
        $bytes = random_bytes(CsrfToken::MIN_BYTES);
        $token = new CsrfToken(base64_encode($bytes));

        $this->assertSame(base64_encode($bytes), $token->value());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function controlCharacterProvider(): array
    {
        return [
            'semicolon'       => [';'],
            'newline'         => ["\n"],
            'carriage return' => ["\r"],
        ];
    }

    #[DataProvider('controlCharacterProvider')]
    public function testRejectsControlCharacters(string $char): void
    {
        $this->expectException(InvalidCsrfTokenException::class);

        new CsrfToken(base64_encode(random_bytes(32)) . $char);
    }
}
