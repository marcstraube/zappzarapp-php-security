<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Sri\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Sri\Exception\HashMismatchException;

#[CoversClass(HashMismatchException::class)]
final class HashMismatchExceptionTest extends TestCase
{
    public function testExtendsRuntimeException(): void
    {
        $exception = HashMismatchException::mismatch('expected', 'actual');

        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    public function testConstructor(): void
    {
        $expected  = 'sha384-expectedhash123456';
        $actual    = 'sha384-actualhash789012';
        $exception = new HashMismatchException($expected, $actual);

        $this->assertSame('Resource hash does not match expected value', $exception->getMessage());
        $this->assertSame($expected, $exception->expected());
        $this->assertSame($actual, $exception->actual());
    }

    public function testMismatchFactoryMethod(): void
    {
        $expected  = 'sha384-abc123def456';
        $actual    = 'sha384-xyz789uvw012';
        $exception = HashMismatchException::mismatch($expected, $actual);

        $this->assertInstanceOf(HashMismatchException::class, $exception);
        $this->assertSame($expected, $exception->expected());
        $this->assertSame($actual, $exception->actual());
    }

    public function testExpectedReturnsCorrectValue(): void
    {
        $expected  = 'sha384-qwertyuiopasdfghjkl';
        $exception = new HashMismatchException($expected, 'any');

        $this->assertSame($expected, $exception->expected());
    }

    public function testActualReturnsCorrectValue(): void
    {
        $actual    = 'sha512-zxcvbnm1234567890';
        $exception = new HashMismatchException('any', $actual);

        $this->assertSame($actual, $exception->actual());
    }

    public function testWithValidSriHashes(): void
    {
        // Real-looking SRI hashes
        $expected = 'sha384-' . base64_encode(hash('sha384', 'expected content', true));
        $actual   = 'sha384-' . base64_encode(hash('sha384', 'actual content', true));

        $exception = HashMismatchException::mismatch($expected, $actual);

        $this->assertSame($expected, $exception->expected());
        $this->assertSame($actual, $exception->actual());
    }

    public function testWithMultipleHashes(): void
    {
        $expected = 'sha384-hash1 sha512-hash2';
        $actual   = 'sha384-hash3 sha512-hash4';

        $exception = HashMismatchException::mismatch($expected, $actual);

        $this->assertSame($expected, $exception->expected());
        $this->assertSame($actual, $exception->actual());
    }

    public function testWithEmptyHashes(): void
    {
        $exception = HashMismatchException::mismatch('', '');

        $this->assertSame('', $exception->expected());
        $this->assertSame('', $exception->actual());
    }

    public function testMessageIsConsistent(): void
    {
        $exception1 = new HashMismatchException('hash1', 'hash2');
        $exception2 = HashMismatchException::mismatch('hash3', 'hash4');

        $this->assertSame($exception1->getMessage(), $exception2->getMessage());
        $this->assertSame('Resource hash does not match expected value', $exception1->getMessage());
    }

    public function testImmutabilityOfExpectedAndActual(): void
    {
        $exception = HashMismatchException::mismatch('expected', 'actual');

        // Call methods multiple times to ensure they return same value
        $this->assertSame($exception->expected(), $exception->expected());
        $this->assertSame($exception->actual(), $exception->actual());
    }
}
