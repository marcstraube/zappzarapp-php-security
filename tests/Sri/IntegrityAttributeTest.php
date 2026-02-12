<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sri\Exception\InvalidHashException;
use Zappzarapp\Security\Sri\HashAlgorithm;
use Zappzarapp\Security\Sri\IntegrityAttribute;

#[CoversClass(IntegrityAttribute::class)]
final class IntegrityAttributeTest extends TestCase
{
    public function testFromContent(): void
    {
        $content   = 'alert("Hello, world!");';
        $integrity = IntegrityAttribute::fromContent($content);

        $this->assertInstanceOf(IntegrityAttribute::class, $integrity);
        $this->assertStringStartsWith('sha384-', $integrity->value());
    }

    public function testFromContentWithAlgorithm(): void
    {
        $content   = 'alert("Hello, world!");';
        $integrity = IntegrityAttribute::fromContent($content, HashAlgorithm::SHA512);

        $this->assertStringStartsWith('sha512-', $integrity->value());
    }

    public function testFromHash(): void
    {
        $hash      = base64_encode(hash('sha384', 'test', true));
        $integrity = IntegrityAttribute::fromHash(HashAlgorithm::SHA384, $hash);

        $this->assertSame('sha384-' . $hash, $integrity->value());
    }

    public function testFromString(): void
    {
        $hash      = base64_encode(hash('sha384', 'test', true));
        $string    = 'sha384-' . $hash;
        $integrity = IntegrityAttribute::fromString($string);

        $this->assertSame($string, $integrity->value());
    }

    public function testFromStringWithMultipleHashes(): void
    {
        $hash384   = base64_encode(hash('sha384', 'test', true));
        $hash512   = base64_encode(hash('sha512', 'test', true));
        $string    = 'sha384-' . $hash384 . ' sha512-' . $hash512;
        $integrity = IntegrityAttribute::fromString($string);

        $hashes = $integrity->hashes();
        $this->assertCount(2, $hashes);
    }

    public function testFromStringTrimsWhitespace(): void
    {
        $hash      = base64_encode(hash('sha384', 'test', true));
        $string    = '  sha384-' . $hash . '  ';
        $integrity = IntegrityAttribute::fromString($string);

        $this->assertSame('sha384-' . $hash, $integrity->value());
    }

    public function testFromStringRejectsPrefixBeforeAlgorithm(): void
    {
        $hash = base64_encode(hash('sha384', 'test', true));

        $this->expectException(InvalidHashException::class);

        IntegrityAttribute::fromString('prefix-sha384-' . $hash);
    }

    public function testFromStringRejectsSuffixAfterHash(): void
    {
        $hash = base64_encode(hash('sha384', 'test', true));

        $this->expectException(InvalidHashException::class);

        IntegrityAttribute::fromString('sha384-' . $hash . '-suffix');
    }

    public function testFromStringRejectsInvalidFormat(): void
    {
        $this->expectException(InvalidHashException::class);

        IntegrityAttribute::fromString('invalid-hash');
    }

    public function testFromStringRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(InvalidHashException::class);

        IntegrityAttribute::fromString('md5-YWJjZGVm');
    }

    public function testConstructorRejectsEmptyHashes(): void
    {
        $this->expectException(InvalidHashException::class);

        new IntegrityAttribute([]);
    }

    public function testWithHash(): void
    {
        $content   = 'test';
        $integrity = IntegrityAttribute::fromContent($content, HashAlgorithm::SHA384);
        $hash512   = base64_encode(hash('sha512', $content, true));

        $newIntegrity = $integrity->withHash(HashAlgorithm::SHA512, $hash512);

        $this->assertCount(1, $integrity->hashes());
        $this->assertCount(2, $newIntegrity->hashes());
    }

    public function testPrimaryHash(): void
    {
        $content   = 'test';
        $integrity = IntegrityAttribute::fromContent($content, HashAlgorithm::SHA384);

        $primary = $integrity->primaryHash();

        $this->assertSame(HashAlgorithm::SHA384, $primary['algorithm']);
    }

    public function testVerifyCorrectContent(): void
    {
        $content   = 'alert("Hello!");';
        $integrity = IntegrityAttribute::fromContent($content);

        $this->assertTrue($integrity->verify($content));
    }

    public function testVerifyIncorrectContent(): void
    {
        $content   = 'alert("Hello!");';
        $integrity = IntegrityAttribute::fromContent($content);

        $this->assertFalse($integrity->verify('alert("Goodbye!");'));
    }

    public function testValue(): void
    {
        $content   = 'test';
        $integrity = IntegrityAttribute::fromContent($content, HashAlgorithm::SHA384);

        $value = $integrity->value();

        $this->assertStringStartsWith('sha384-', $value);
        $this->assertMatchesRegularExpression('/^sha384-[A-Za-z0-9+\/=]+$/', $value);
    }

    public function testToString(): void
    {
        $content   = 'test';
        $integrity = IntegrityAttribute::fromContent($content);

        $this->assertSame($integrity->value(), (string) $integrity);
    }

    public function testImmutability(): void
    {
        $content   = 'test';
        $integrity = IntegrityAttribute::fromContent($content, HashAlgorithm::SHA384);
        $hash512   = base64_encode(hash('sha512', $content, true));

        $integrity->withHash(HashAlgorithm::SHA512, $hash512);

        $this->assertCount(1, $integrity->hashes());
    }

    public function testHashesReturnsCorrectStructure(): void
    {
        $content   = 'test';
        $integrity = IntegrityAttribute::fromContent($content, HashAlgorithm::SHA384);

        $hashes = $integrity->hashes();

        $this->assertCount(1, $hashes);
        $this->assertArrayHasKey('algorithm', $hashes[0]);
        $this->assertArrayHasKey('hash', $hashes[0]);
        $this->assertSame(HashAlgorithm::SHA384, $hashes[0]['algorithm']);
    }

    public function testFromHashRejectsInvalidBase64(): void
    {
        $this->expectException(InvalidHashException::class);

        IntegrityAttribute::fromHash(HashAlgorithm::SHA384, 'not-valid-base64!!!');
    }

    public function testFromHashRejectsWrongLength(): void
    {
        $this->expectException(InvalidHashException::class);

        IntegrityAttribute::fromHash(HashAlgorithm::SHA384, base64_encode('short'));
    }
}
