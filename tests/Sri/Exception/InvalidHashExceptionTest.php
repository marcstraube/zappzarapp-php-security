<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Sri\Exception\InvalidHashException;

#[CoversClass(InvalidHashException::class)]
final class InvalidHashExceptionTest extends TestCase
{
    #[Test]
    public function testExtendsInvalidArgumentException(): void
    {
        $exception = InvalidHashException::invalidFormat('test');

        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
    }

    #[Test]
    public function testInvalidFormatFactoryMethod(): void
    {
        $hash      = 'not-a-valid-hash-format';
        $exception = InvalidHashException::invalidFormat($hash);

        $this->assertStringContainsString('Invalid SRI hash format:', $exception->getMessage());
        $this->assertStringContainsString($hash, $exception->getMessage());
    }

    #[Test]
    public function testUnsupportedAlgorithmFactoryMethod(): void
    {
        $algorithm = 'md5';
        $exception = InvalidHashException::unsupportedAlgorithm($algorithm);

        $this->assertStringContainsString('Unsupported SRI hash algorithm:', $exception->getMessage());
        $this->assertStringContainsString($algorithm, $exception->getMessage());
        $this->assertStringContainsString('sha384, sha512', $exception->getMessage());
    }

    #[Test]
    public function testInvalidBase64FactoryMethod(): void
    {
        $hash      = 'not!!!valid+++base64';
        $exception = InvalidHashException::invalidBase64($hash);

        $this->assertStringContainsString('SRI hash contains invalid base64:', $exception->getMessage());
        $this->assertStringContainsString($hash, $exception->getMessage());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidFormatProvider(): array
    {
        return [
            'missing algorithm'           => ['YWJjZGVm'],
            'missing hash'                => ['sha384-'],
            'invalid separator'           => ['sha384_YWJjZGVm'],
            'double separator'            => ['sha384--YWJjZGVm'],
            'space instead of separator'  => ['sha384 YWJjZGVm'],
            'unknown prefix'              => ['integrity-YWJjZGVm'],
            'empty string'                => [''],
        ];
    }

    #[DataProvider('invalidFormatProvider')]
    #[Test]
    public function testInvalidFormatWithVariousInputs(string $hash): void
    {
        $exception = InvalidHashException::invalidFormat($hash);

        $this->assertStringContainsString('Invalid SRI hash format:', $exception->getMessage());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function unsupportedAlgorithmProvider(): array
    {
        return [
            'MD5'       => ['md5'],
            'SHA1'      => ['sha1'],
            'SHA-1'     => ['sha-1'],
            'SHA224'    => ['sha224'],
            'MD4'       => ['md4'],
            'RIPEMD'    => ['ripemd160'],
            'Whirlpool' => ['whirlpool'],
            'Unknown'   => ['custom'],
        ];
    }

    #[DataProvider('unsupportedAlgorithmProvider')]
    #[Test]
    public function testUnsupportedAlgorithmWithVariousInputs(string $algorithm): void
    {
        $exception = InvalidHashException::unsupportedAlgorithm($algorithm);

        $this->assertStringContainsString($algorithm, $exception->getMessage());
        $this->assertStringContainsString('sha384, sha512', $exception->getMessage());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidBase64Provider(): array
    {
        return [
            'invalid characters'    => ['!!!invalid!!!'],
            'spaces'                => ['abc def ghi'],
            'special characters'    => ['abc@#$%def'],
            'newlines'              => ["abc\ndef"],
            'unicode'               => ['abc\u0000def'],
            'incomplete padding'    => ['YWJj='],
            'too much padding'      => ['YWJj===='],
        ];
    }

    #[DataProvider('invalidBase64Provider')]
    #[Test]
    public function testInvalidBase64WithVariousInputs(string $hash): void
    {
        $exception = InvalidHashException::invalidBase64($hash);

        $this->assertStringContainsString('SRI hash contains invalid base64:', $exception->getMessage());
    }

    #[Test]
    public function testInvalidFormatWithLongHash(): void
    {
        $longHash  = str_repeat('a', 500);
        $exception = InvalidHashException::invalidFormat($longHash);

        $this->assertStringContainsString($longHash, $exception->getMessage());
    }

    #[Test]
    public function testUnsupportedAlgorithmWithUppercase(): void
    {
        $exception = InvalidHashException::unsupportedAlgorithm('MD5');

        $this->assertStringContainsString('MD5', $exception->getMessage());
    }

    #[Test]
    public function testInvalidBase64WithValidLookingButWrongHash(): void
    {
        // Looks like base64 but might be wrong length for algorithm
        $hash      = base64_encode('too-short');
        $exception = InvalidHashException::invalidBase64($hash);

        $this->assertStringContainsString($hash, $exception->getMessage());
    }

    #[Test]
    public function testAllFactoryMethodsReturnSameExceptionClass(): void
    {
        $format    = InvalidHashException::invalidFormat('test');
        $algorithm = InvalidHashException::unsupportedAlgorithm('md5');
        $base64    = InvalidHashException::invalidBase64('invalid');

        $this->assertInstanceOf(InvalidHashException::class, $format);
        $this->assertInstanceOf(InvalidHashException::class, $algorithm);
        $this->assertInstanceOf(InvalidHashException::class, $base64);
    }
}
