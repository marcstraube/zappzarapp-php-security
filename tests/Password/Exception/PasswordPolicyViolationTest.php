<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Password\Exception;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Password\Exception\PasswordPolicyViolation;

#[CoversClass(PasswordPolicyViolation::class)]
final class PasswordPolicyViolationTest extends TestCase
{
    #[Test]
    public function testExtendsInvalidArgumentException(): void
    {
        $exception = new PasswordPolicyViolation(['Violation']);

        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
    }

    #[Test]
    public function testConstructorSetsViolations(): void
    {
        $violations = ['Must be longer', 'Must contain digit'];
        $exception  = new PasswordPolicyViolation($violations);

        $this->assertSame($violations, $exception->violations());
    }

    #[Test]
    public function testConstructorSetsMessage(): void
    {
        $violations = ['Must be longer', 'Must contain digit'];
        $exception  = new PasswordPolicyViolation($violations);

        $this->assertSame(
            'Password does not meet policy requirements: Must be longer, Must contain digit',
            $exception->getMessage()
        );
    }

    #[Test]
    public function testConstructorWithSingleViolation(): void
    {
        $exception = new PasswordPolicyViolation(['Single violation']);

        $this->assertSame(
            'Password does not meet policy requirements: Single violation',
            $exception->getMessage()
        );
        $this->assertCount(1, $exception->violations());
    }

    #[Test]
    public function testConstructorWithEmptyViolations(): void
    {
        $exception = new PasswordPolicyViolation([]);

        $this->assertSame(
            'Password does not meet policy requirements: ',
            $exception->getMessage()
        );
        $this->assertSame([], $exception->violations());
    }

    #[Test]
    public function testMinLengthFactoryMethod(): void
    {
        $exception = PasswordPolicyViolation::minLength(12, 5);

        $this->assertSame(
            'Password does not meet policy requirements: Password must be at least 12 characters (got 5)',
            $exception->getMessage()
        );
        $this->assertSame(
            ['Password must be at least 12 characters (got 5)'],
            $exception->violations()
        );
    }

    #[Test]
    public function testMinLengthWithZeroActual(): void
    {
        $exception = PasswordPolicyViolation::minLength(8, 0);

        $this->assertStringContainsString('at least 8 characters (got 0)', $exception->getMessage());
    }

    #[Test]
    public function testMaxLengthFactoryMethod(): void
    {
        $exception = PasswordPolicyViolation::maxLength(128, 200);

        $this->assertSame(
            'Password does not meet policy requirements: Password must not exceed 128 characters (got 200)',
            $exception->getMessage()
        );
        $this->assertSame(
            ['Password must not exceed 128 characters (got 200)'],
            $exception->violations()
        );
    }

    #[Test]
    public function testMissingCharacterClassFactoryMethod(): void
    {
        $exception = PasswordPolicyViolation::missingCharacterClass('uppercase');

        $this->assertSame(
            'Password does not meet policy requirements: Password must contain at least one uppercase character',
            $exception->getMessage()
        );
        $this->assertSame(
            ['Password must contain at least one uppercase character'],
            $exception->violations()
        );
    }

    #[Test]
    public function testMissingCharacterClassWithDifferentClasses(): void
    {
        $classes = ['lowercase', 'digit', 'special'];

        foreach ($classes as $class) {
            $exception = PasswordPolicyViolation::missingCharacterClass($class);

            $this->assertStringContainsString($class, $exception->getMessage());
        }
    }

    #[Test]
    public function testMultipleFactoryMethod(): void
    {
        $violations = [
            'Password too short',
            'Missing uppercase',
            'Missing digit',
        ];
        $exception = PasswordPolicyViolation::multiple($violations);

        $this->assertSame($violations, $exception->violations());
        $this->assertStringContainsString('Password too short', $exception->getMessage());
        $this->assertStringContainsString('Missing uppercase', $exception->getMessage());
        $this->assertStringContainsString('Missing digit', $exception->getMessage());
    }

    #[Test]
    public function testMultipleWithEmptyArray(): void
    {
        $exception = PasswordPolicyViolation::multiple([]);

        $this->assertSame([], $exception->violations());
    }

    #[Test]
    public function testViolationsReturnsNewArray(): void
    {
        $violations = ['Violation 1', 'Violation 2'];
        $exception  = new PasswordPolicyViolation($violations);

        $returned1 = $exception->violations();
        $returned2 = $exception->violations();

        $this->assertSame($returned1, $returned2);
        $this->assertSame($violations, $returned1);
    }

    #[Test]
    public function testWithUnicodeViolationMessages(): void
    {
        $violations = ['Passwort muss Grossbuchstaben enthalten', 'Mindestens 8 Zeichen erforderlich'];
        $exception  = new PasswordPolicyViolation($violations);

        $this->assertSame($violations, $exception->violations());
    }

    #[Test]
    public function testWithSpecialCharactersInViolationMessages(): void
    {
        $violations = ['Must contain: !@#$%^&*()', 'Length < 8'];
        $exception  = new PasswordPolicyViolation($violations);

        $this->assertSame($violations, $exception->violations());
    }
}
