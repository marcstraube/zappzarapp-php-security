<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Secrets;

use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use Stringable;
use Zappzarapp\Security\Secrets\Exception\InvalidSecretValueException;
use Zappzarapp\Security\Secrets\SecretValue;

#[CoversClass(SecretValue::class)]
#[CoversClass(InvalidSecretValueException::class)]
final class SecretValueTest extends TestCase
{
    #[Test]
    public function testRevealReturnsWrappedValue(): void
    {
        $secret = new SecretValue('s3cr3t-value');

        $this->assertSame('s3cr3t-value', $secret->reveal());
    }

    #[Test]
    public function testRejectsEmptyValue(): void
    {
        $this->expectException(InvalidSecretValueException::class);
        $this->expectExceptionMessage('Secret value must not be empty');

        new SecretValue('');
    }

    #[Test]
    public function testRevealedCopySurvivesDestruction(): void
    {
        $secret = new SecretValue('survives-destruct');
        $copy   = $secret->reveal();

        unset($secret);

        $this->assertSame('survives-destruct', $copy);
    }

    #[Test]
    public function testEqualsReturnsTrueForSameValue(): void
    {
        $first  = new SecretValue('same-value');
        $second = new SecretValue('same-value');

        $this->assertTrue($first->equals($second));
    }

    #[Test]
    public function testEqualsReturnsFalseForDifferentValues(): void
    {
        $first  = new SecretValue('one-value');
        $second = new SecretValue('another-value');

        $this->assertFalse($first->equals($second));
    }

    #[Test]
    public function testEqualsReturnsFalseForDifferentLengths(): void
    {
        $first  = new SecretValue('short');
        $second = new SecretValue('short-but-longer');

        $this->assertFalse($first->equals($second));
    }

    #[Test]
    public function testDebugInfoRedactsValue(): void
    {
        $secret = new SecretValue('do-not-leak');

        $this->assertSame(['value' => '***REDACTED***'], $secret->__debugInfo());
    }

    #[Test]
    public function testJsonEncodeRedactsValue(): void
    {
        $secret = new SecretValue('do-not-leak');

        $this->assertSame('"***REDACTED***"', json_encode($secret));
    }

    #[Test]
    public function testJsonEncodeRedactsValueInContext(): void
    {
        $context = ['db_password' => new SecretValue('do-not-leak')];

        $this->assertSame('{"db_password":"***REDACTED***"}', json_encode($context));
    }

    #[Test]
    public function testSerializeThrows(): void
    {
        $secret = new SecretValue('do-not-leak');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('SecretValue must not be serialized');

        serialize($secret);
    }

    #[Test]
    public function testUnserializeThrows(): void
    {
        $payload = 'O:39:"Zappzarapp\\Security\\Secrets\\SecretValue":1:{s:5:"value";s:4:"leak";}';

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('SecretValue must not be unserialized');

        unserialize($payload);
    }

    #[Test]
    public function testIsNotStringable(): void
    {
        $secret = new SecretValue('do-not-leak');

        $this->assertNotInstanceOf(Stringable::class, $secret);
    }

    #[Test]
    public function testDestructZeroesInternalBuffer(): void
    {
        $secret = new SecretValue('zero-me-out');

        $secret->__destruct();

        $property = new ReflectionProperty(SecretValue::class, 'value');
        $this->assertNull($property->getValue($secret));
    }

    #[Test]
    public function testRevealThrowsAfterClearing(): void
    {
        $secret = new SecretValue('cleared-secret');
        $secret->__destruct();

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('SecretValue has already been cleared');

        $secret->reveal();
    }

    #[Test]
    public function testEqualsThrowsAfterClearing(): void
    {
        $cleared = new SecretValue('cleared-secret');
        $cleared->__destruct();

        $intact = new SecretValue('intact-secret');

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('SecretValue has already been cleared');

        $intact->equals($cleared);
    }

    #[Test]
    public function testDestructIsIdempotent(): void
    {
        $secret = new SecretValue('zero-me-out');

        $secret->__destruct();
        $secret->__destruct();

        $property = new ReflectionProperty(SecretValue::class, 'value');
        $this->assertNull($property->getValue($secret));
    }
}
