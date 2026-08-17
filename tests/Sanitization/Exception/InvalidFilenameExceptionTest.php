<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sanitization\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sanitization\Exception\InvalidFilenameException;

#[CoversClass(InvalidFilenameException::class)]
final class InvalidFilenameExceptionTest extends TestCase
{
    #[Test]
    public function testExtendsInvalidArgumentException(): void
    {
        $this->assertInstanceOf(InvalidArgumentException::class, InvalidFilenameException::nullByte());
    }

    #[Test]
    public function testNullByte(): void
    {
        $this->assertSame(
            'Filename contains a NUL byte',
            InvalidFilenameException::nullByte()->getMessage()
        );
    }

    #[Test]
    public function testControlCharacter(): void
    {
        $this->assertSame(
            'Filename contains control characters',
            InvalidFilenameException::controlCharacter()->getMessage()
        );
    }

    #[Test]
    public function testInvalidEncoding(): void
    {
        $this->assertSame(
            'Filename is not valid UTF-8',
            InvalidFilenameException::invalidEncoding()->getMessage()
        );
    }

    #[Test]
    public function testUnsafeUnicode(): void
    {
        $this->assertSame(
            'Filename contains bidirectional or zero-width characters',
            InvalidFilenameException::unsafeUnicode()->getMessage()
        );
    }

    #[Test]
    public function testTraversal(): void
    {
        $this->assertSame(
            'Filename is a directory traversal sequence',
            InvalidFilenameException::traversal()->getMessage()
        );
    }

    #[Test]
    public function testEmptyResult(): void
    {
        $this->assertSame(
            'Filename contains no usable characters',
            InvalidFilenameException::emptyResult()->getMessage()
        );
    }

    #[Test]
    public function testReservedName(): void
    {
        $this->assertSame(
            'Filename "NUL.txt" is a reserved device name',
            InvalidFilenameException::reservedName('NUL.txt')->getMessage()
        );
    }

    #[Test]
    public function testTooLong(): void
    {
        $this->assertSame(
            'Filename is 300 bytes long, the maximum is 255',
            InvalidFilenameException::tooLong(300, 255)->getMessage()
        );
    }

    #[Test]
    public function testMessagesNeverCarryTheRawFilename(): void
    {
        // The client filename is attacker controlled, so it must not be
        // interpolated into a message that reaches a log or a header
        $messages = [
            InvalidFilenameException::nullByte()->getMessage(),
            InvalidFilenameException::controlCharacter()->getMessage(),
            InvalidFilenameException::invalidEncoding()->getMessage(),
            InvalidFilenameException::unsafeUnicode()->getMessage(),
            InvalidFilenameException::traversal()->getMessage(),
            InvalidFilenameException::emptyResult()->getMessage(),
        ];

        foreach ($messages as $message) {
            $this->assertSame($message, trim($message));
            $this->assertDoesNotMatchRegularExpression('/[\x00-\x1F\x7F]/', $message);
        }
    }
}
