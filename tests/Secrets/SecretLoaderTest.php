<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Secrets;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Secrets\Exception\InvalidSecretNameException;
use Zappzarapp\Security\Secrets\Exception\SecretLoadException;
use Zappzarapp\Security\Secrets\Exception\SecretNotFoundException;
use Zappzarapp\Security\Secrets\FileSecretSource;
use Zappzarapp\Security\Secrets\SecretLoader;
use Zappzarapp\Security\Secrets\SecretName;
use Zappzarapp\Security\Secrets\SecretSourceInterface;
use Zappzarapp\Security\Secrets\SecretValue;

#[CoversClass(SecretLoader::class)]
#[CoversClass(SecretNotFoundException::class)]
#[CoversClass(SecretLoadException::class)]
#[UsesClass(FileSecretSource::class)]
#[UsesClass(SecretName::class)]
#[UsesClass(SecretValue::class)]
#[UsesClass(InvalidSecretNameException::class)]
final class SecretLoaderTest extends TestCase
{
    #[Test]
    public function testLoadReturnsSecretFromFirstSource(): void
    {
        $loader = new SecretLoader($this->sourceWith('first-value'), $this->sourceWith('second-value'));

        $this->assertSame('first-value', $loader->load('db_password')->reveal());
    }

    #[Test]
    public function testLoadFallsThroughToNextSource(): void
    {
        $loader = new SecretLoader($this->sourceWith(null), $this->sourceWith('fallback-value'));

        $this->assertSame('fallback-value', $loader->load('db_password')->reveal());
    }

    #[Test]
    public function testLoadAcceptsSecretNameObject(): void
    {
        $loader = new SecretLoader($this->sourceWith('by-object'));

        $this->assertSame('by-object', $loader->load(new SecretName('db_password'))->reveal());
    }

    #[Test]
    public function testLoadThrowsWhenNoSourceHasSecret(): void
    {
        $loader = new SecretLoader(
            $this->sourceWith(null, 'file:/run/secrets'),
            $this->sourceWith(null, 'env')
        );

        $this->expectException(SecretNotFoundException::class);
        $this->expectExceptionMessage('Secret "db_password" not found (searched: file:/run/secrets, env)');

        $loader->load('db_password');
    }

    #[Test]
    public function testLoadThrowsForEmptySecret(): void
    {
        $loader = new SecretLoader($this->sourceWith('', 'file:/run/secrets'));

        $this->expectException(SecretLoadException::class);
        $this->expectExceptionMessage('Secret "db_password" in source "file:/run/secrets" is empty');

        $loader->load('db_password');
    }

    #[Test]
    public function testLoadDoesNotFallThroughAfterEmptySecret(): void
    {
        $loader = new SecretLoader($this->sourceWith(''), $this->unreachableSource());

        $this->expectException(SecretLoadException::class);

        $loader->load('db_password');
    }

    #[Test]
    public function testLoadValidatesStringName(): void
    {
        $loader = new SecretLoader($this->sourceWith('value'));

        $this->expectException(InvalidSecretNameException::class);

        $loader->load('../etc/passwd');
    }

    #[Test]
    public function testTryLoadReturnsSecretWhenFound(): void
    {
        $loader = new SecretLoader($this->sourceWith('found-value'));

        $secret = $loader->tryLoad('db_password');

        $this->assertInstanceOf(SecretValue::class, $secret);
        $this->assertSame('found-value', $secret->reveal());
    }

    #[Test]
    public function testTryLoadReturnsNullWhenNotFound(): void
    {
        $loader = new SecretLoader($this->sourceWith(null));

        $this->assertNull($loader->tryLoad('db_password'));
    }

    #[Test]
    public function testTryLoadStillThrowsForEmptySecret(): void
    {
        $loader = new SecretLoader($this->sourceWith(''));

        $this->expectException(SecretLoadException::class);

        $loader->tryLoad('db_password');
    }

    #[Test]
    public function testTryLoadStillThrowsForInvalidName(): void
    {
        $loader = new SecretLoader($this->sourceWith('value'));

        $this->expectException(InvalidSecretNameException::class);

        $loader->tryLoad('a/b');
    }

    #[Test]
    public function testDockerFactoryUsesDockerSecretsMount(): void
    {
        $loader = SecretLoader::docker();

        $this->expectException(SecretNotFoundException::class);
        $this->expectExceptionMessage('(searched: file:/run/secrets)');

        $loader->load('zztest_nonexistent_secret');
    }

    private function sourceWith(?string $value, string $description = 'stub'): SecretSourceInterface
    {
        return new class($value, $description) implements SecretSourceInterface {
            public function __construct(
                private readonly ?string $value,
                private readonly string $description,
            ) {
            }

            public function fetch(SecretName $name): ?string
            {
                return $this->value;
            }

            public function describe(): string
            {
                return $this->description;
            }
        };
    }

    private function unreachableSource(): SecretSourceInterface
    {
        return new class($this) implements SecretSourceInterface {
            public function __construct(private readonly TestCase $testCase)
            {
            }

            public function fetch(SecretName $name): ?string
            {
                $this->testCase::fail('Source must not be consulted after an empty secret');
            }

            public function describe(): string
            {
                return 'unreachable';
            }
        };
    }
}
