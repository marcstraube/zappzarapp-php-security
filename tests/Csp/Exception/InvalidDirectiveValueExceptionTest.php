<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;

final class InvalidDirectiveValueExceptionTest extends TestCase
{
    #[Test]
    public function testExtendsInvalidArgumentException(): void
    {
        $exception = InvalidDirectiveValueException::containsSemicolon('test', 'value');

        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies type inheritance */
        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
    }

    #[Test]
    public function testContainsSemicolonMessage(): void
    {
        $exception = InvalidDirectiveValueException::containsSemicolon('script-src', "'self'; evil");

        $this->assertStringContainsString('script-src', $exception->getMessage());
        $this->assertStringContainsString('semicolon', $exception->getMessage());
        $this->assertStringContainsString("'self'; evil", $exception->getMessage());
    }

    #[Test]
    public function testContainsControlCharacterWithLineFeed(): void
    {
        $exception = InvalidDirectiveValueException::containsControlCharacter('default-src', "'self'\nevil");

        $this->assertStringContainsString('default-src', $exception->getMessage());
        $this->assertStringContainsString('control character', $exception->getMessage());
        $this->assertStringContainsString('\\x0A', $exception->getMessage());
    }

    #[Test]
    public function testContainsControlCharacterWithCarriageReturn(): void
    {
        $exception = InvalidDirectiveValueException::containsControlCharacter('style-src', "'self'\revil");

        $this->assertStringContainsString('style-src', $exception->getMessage());
        $this->assertStringContainsString('\\x0D', $exception->getMessage());
    }

    #[Test]
    public function testContainsControlCharacterWithNullByte(): void
    {
        $exception = InvalidDirectiveValueException::containsControlCharacter('script-src', "'self'\x00evil");

        $this->assertStringContainsString('script-src', $exception->getMessage());
        $this->assertStringContainsString('\\x00', $exception->getMessage());
        $this->assertStringContainsString('control character', $exception->getMessage());
    }

    #[Test]
    public function testContainsControlCharacterWithTab(): void
    {
        $exception = InvalidDirectiveValueException::containsControlCharacter('script-src', "'self'\tevil");

        $this->assertStringContainsString('\\x09', $exception->getMessage());
    }

    #[Test]
    public function testInvalidWebSocketHostMessage(): void
    {
        $exception = InvalidDirectiveValueException::invalidWebSocketHost('invalid-host');

        $this->assertStringContainsString('WebSocket', $exception->getMessage());
        $this->assertStringContainsString('invalid-host', $exception->getMessage());
        $this->assertStringContainsString('host:port', $exception->getMessage());
    }

    #[Test]
    public function testInvalidWebSocketPortMessage(): void
    {
        $exception = InvalidDirectiveValueException::invalidWebSocketPort('localhost:99999', 99999);

        $this->assertStringContainsString('WebSocket', $exception->getMessage());
        $this->assertStringContainsString('localhost:99999', $exception->getMessage());
        $this->assertStringContainsString('99999', $exception->getMessage());
        $this->assertStringContainsString('1 and 65535', $exception->getMessage());
    }

    #[Test]
    public function testInvalidNonceMessage(): void
    {
        $exception = InvalidDirectiveValueException::invalidNonce('evil;nonce', 'contains semicolon');

        $this->assertStringContainsString('Nonce', $exception->getMessage());
        $this->assertStringContainsString('contains semicolon', $exception->getMessage());
        $this->assertStringContainsString('evil;nonce', $exception->getMessage());
    }

    #[Test]
    public function testInvalidNonceEscapesControlCharacters(): void
    {
        $exception = InvalidDirectiveValueException::invalidNonce("evil\nnonce", 'contains control character');

        $this->assertStringContainsString('\\x0A', $exception->getMessage());
        $this->assertStringNotContainsString("\n", $exception->getMessage());
    }

    #[Test]
    public function testContainsUnicodeWhitespaceMessage(): void
    {
        $exception = InvalidDirectiveValueException::containsUnicodeWhitespace('script-src', "'self'\u{00A0}'unsafe-inline'");

        $this->assertStringContainsString('script-src', $exception->getMessage());
        $this->assertStringContainsString('unicode whitespace', $exception->getMessage());
        $this->assertStringContainsString('parser inconsistencies', $exception->getMessage());
    }
}
