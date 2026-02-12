<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Zappzarapp\Security\Password\Exception\WeakPasswordException;

#[CoversClass(WeakPasswordException::class)]
final class WeakPasswordExceptionTest extends TestCase
{
    public function testExtendsRuntimeException(): void
    {
        $exception = WeakPasswordException::commonPassword();

        $this->assertInstanceOf(RuntimeException::class, $exception);
    }

    public function testLowEntropyFactoryMethod(): void
    {
        $exception = WeakPasswordException::lowEntropy(25.5, 60.0);

        $this->assertSame(
            'Password entropy too low: 25.5 bits (minimum 60.0 bits required)',
            $exception->getMessage()
        );
    }

    public function testLowEntropyWithWholeNumbers(): void
    {
        $exception = WeakPasswordException::lowEntropy(30.0, 50.0);

        $this->assertSame(
            'Password entropy too low: 30.0 bits (minimum 50.0 bits required)',
            $exception->getMessage()
        );
    }

    public function testLowEntropyWithZeroEntropy(): void
    {
        $exception = WeakPasswordException::lowEntropy(0.0, 60.0);

        $this->assertSame(
            'Password entropy too low: 0.0 bits (minimum 60.0 bits required)',
            $exception->getMessage()
        );
    }

    public function testLowEntropyWithPrecision(): void
    {
        $exception = WeakPasswordException::lowEntropy(28.123456, 60.789012);

        $this->assertStringContainsString('28.1', $exception->getMessage());
        $this->assertStringContainsString('60.8', $exception->getMessage());
    }

    public function testCommonPasswordFactoryMethod(): void
    {
        $exception = WeakPasswordException::commonPassword();

        $this->assertSame(
            'Password is too common or easily guessable',
            $exception->getMessage()
        );
    }

    public function testPatternDetectedFactoryMethod(): void
    {
        $exception = WeakPasswordException::patternDetected('sequential numbers');

        $this->assertSame(
            'Password contains weak pattern: sequential numbers',
            $exception->getMessage()
        );
    }

    public function testPatternDetectedWithDifferentPatterns(): void
    {
        $patterns = [
            'keyboard walk',
            'repeated characters',
            'common substitution',
            'date format',
        ];

        foreach ($patterns as $pattern) {
            $exception = WeakPasswordException::patternDetected($pattern);

            $this->assertStringContainsString($pattern, $exception->getMessage());
        }
    }

    public function testPatternDetectedWithEmptyPattern(): void
    {
        $exception = WeakPasswordException::patternDetected('');

        $this->assertSame(
            'Password contains weak pattern: ',
            $exception->getMessage()
        );
    }

    public function testPatternDetectedWithSpecialCharacters(): void
    {
        $exception = WeakPasswordException::patternDetected('abc123!@#');

        $this->assertStringContainsString('abc123!@#', $exception->getMessage());
    }
}
