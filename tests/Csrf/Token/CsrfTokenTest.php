<?php

/** @noinspection PhpUnhandledExceptionInspection Tests may throw RandomException */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csrf\Token;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Token\CsrfToken;

#[CoversClass(CsrfToken::class)]
final class CsrfTokenTest extends TestCase
{
    #[Test]
    public function testConstructorWithValidToken(): void
    {
        $value = base64_encode(random_bytes(32));
        $token = new CsrfToken($value);

        $this->assertSame($value, $token->value());
    }

    #[Test]
    public function testConstructorRejectsEmptyToken(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('empty');

        new CsrfToken('');
    }

    #[Test]
    public function testConstructorRejectsSemicolon(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('control characters');

        new CsrfToken('valid' . base64_encode(random_bytes(32)) . ';injection');
    }

    #[Test]
    public function testConstructorRejectsNewline(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('control characters');

        new CsrfToken("valid\ninjection");
    }

    #[Test]
    public function testConstructorRejectsCarriageReturn(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('control characters');

        new CsrfToken("valid\rinjection");
    }

    #[Test]
    public function testConstructorRejectsInvalidBase64(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('base64');

        new CsrfToken('not!valid!base64!!!');
    }

    #[Test]
    public function testConstructorRejectsShortToken(): void
    {
        $this->expectException(InvalidCsrfTokenException::class);
        $this->expectExceptionMessage('entropy');

        new CsrfToken(base64_encode('short'));
    }

    #[Test]
    public function testValue(): void
    {
        $value = base64_encode(random_bytes(32));
        $token = new CsrfToken($value);

        $this->assertSame($value, $token->value());
    }

    #[Test]
    public function testRawBytes(): void
    {
        $bytes = random_bytes(32);
        $value = base64_encode($bytes);
        $token = new CsrfToken($value);

        $this->assertSame($bytes, $token->rawBytes());
    }

    #[Test]
    public function testToString(): void
    {
        $value = base64_encode(random_bytes(32));
        $token = new CsrfToken($value);

        $this->assertSame($value, (string) $token);
    }

    #[Test]
    public function testEquals(): void
    {
        $value  = base64_encode(random_bytes(32));
        $token1 = new CsrfToken($value);
        $token2 = new CsrfToken($value);

        $this->assertTrue($token1->equals($token2));
    }

    #[Test]
    public function testEqualsReturnsFalseForDifferentTokens(): void
    {
        $token1 = new CsrfToken(base64_encode(random_bytes(32)));
        $token2 = new CsrfToken(base64_encode(random_bytes(32)));

        $this->assertFalse($token1->equals($token2));
    }

    #[Test]
    public function testEqualsString(): void
    {
        $value = base64_encode(random_bytes(32));
        $token = new CsrfToken($value);

        $this->assertTrue($token->equalsString($value));
    }

    #[Test]
    public function testEqualsStringReturnsFalse(): void
    {
        $token = new CsrfToken(base64_encode(random_bytes(32)));

        $this->assertFalse($token->equalsString(base64_encode(random_bytes(32))));
    }

    #[Test]
    public function testMinBytesConstant(): void
    {
        $this->assertSame(32, CsrfToken::MIN_BYTES);
    }

    #[Test]
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
    #[Test]
    public function testRejectsControlCharacters(string $char): void
    {
        $this->expectException(InvalidCsrfTokenException::class);

        new CsrfToken(base64_encode(random_bytes(32)) . $char);
    }
}
