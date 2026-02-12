<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Password\Exception\PwnedPasswordException;

#[CoversClass(PwnedPasswordException::class)]
final class PwnedPasswordExceptionTest extends TestCase
{
    public function testExtendsRuntimeException(): void
    {
        $exception = new PwnedPasswordException(1);

        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    public function testConstructorSetsOccurrences(): void
    {
        $exception = new PwnedPasswordException(12345);

        $this->assertSame(12345, $exception->occurrences());
    }

    public function testConstructorSetsSingularMessage(): void
    {
        $exception = new PwnedPasswordException(1);

        $this->assertSame(
            'Password has been exposed in 1 data breach',
            $exception->getMessage()
        );
    }

    public function testConstructorSetsPluralMessage(): void
    {
        $exception = new PwnedPasswordException(5);

        $this->assertSame(
            'Password has been exposed in 5 data breaches',
            $exception->getMessage()
        );
    }

    public function testConstructorWithZeroOccurrences(): void
    {
        $exception = new PwnedPasswordException(0);

        $this->assertSame(0, $exception->occurrences());
        $this->assertSame(
            'Password has been exposed in 0 data breaches',
            $exception->getMessage()
        );
    }

    public function testConstructorWithLargeNumber(): void
    {
        $exception = new PwnedPasswordException(10000000);

        $this->assertSame(10000000, $exception->occurrences());
        $this->assertStringContainsString('10000000', $exception->getMessage());
    }

    public function testBreachedFactoryMethod(): void
    {
        $exception = PwnedPasswordException::breached(500);

        $this->assertSame(500, $exception->occurrences());
        $this->assertSame(
            'Password has been exposed in 500 data breaches',
            $exception->getMessage()
        );
    }

    public function testBreachedFactoryMethodWithSingular(): void
    {
        $exception = PwnedPasswordException::breached(1);

        $this->assertSame(1, $exception->occurrences());
        $this->assertSame(
            'Password has been exposed in 1 data breach',
            $exception->getMessage()
        );
    }

    public function testBreachedFactoryMethodEquivalentToConstructor(): void
    {
        $viaConstructor = new PwnedPasswordException(100);
        $viaFactory     = PwnedPasswordException::breached(100);

        $this->assertSame($viaConstructor->occurrences(), $viaFactory->occurrences());
        $this->assertSame($viaConstructor->getMessage(), $viaFactory->getMessage());
    }

    public function testTwoOccurrencesIsPlural(): void
    {
        $exception = new PwnedPasswordException(2);

        $this->assertStringContainsString('breaches', $exception->getMessage());
    }
}
