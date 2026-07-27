<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Secrets;

use Override;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Secrets\EnvSecretSource;
use Zappzarapp\Security\Secrets\Exception\InvalidEnvPrefixException;
use Zappzarapp\Security\Secrets\SecretName;

#[CoversClass(EnvSecretSource::class)]
#[CoversClass(InvalidEnvPrefixException::class)]
#[UsesClass(SecretName::class)]
final class EnvSecretSourceTest extends TestCase
{
    /**
     * @var list<string>
     */
    private array $environmentVariables = [];

    #[Override]
    protected function tearDown(): void
    {
        foreach ($this->environmentVariables as $variable) {
            putenv($variable);
        }

        $this->environmentVariables = [];
    }

    #[Test]
    public function testFetchReadsEnvironmentVariable(): void
    {
        $this->setEnvironmentVariable('ZZTEST_DB_PASSWORD', 's3cr3t');

        $source = new EnvSecretSource();

        $this->assertSame('s3cr3t', $source->fetch(new SecretName('zztest_db_password')));
    }

    #[Test]
    public function testFetchReturnsNullForUnsetVariable(): void
    {
        $source = new EnvSecretSource();

        $this->assertNull($source->fetch(new SecretName('zztest_never_set_anywhere')));
    }

    #[Test]
    public function testFetchReturnsEmptyStringForEmptyVariable(): void
    {
        $this->setEnvironmentVariable('ZZTEST_EMPTY_SECRET', '');

        $source = new EnvSecretSource();

        $this->assertSame('', $source->fetch(new SecretName('zztest_empty_secret')));
    }

    #[Test]
    public function testFetchTransformsDotsAndHyphens(): void
    {
        $this->setEnvironmentVariable('ZZTEST_APP_DB_PASSWORD', 'transformed');

        $source = new EnvSecretSource();

        $this->assertSame('transformed', $source->fetch(new SecretName('zztest.app.db-password')));
    }

    #[Test]
    public function testFetchAppliesPrefix(): void
    {
        $this->setEnvironmentVariable('ZZAPP_DB_PASSWORD', 'prefixed');

        $source = new EnvSecretSource('ZZAPP_');

        $this->assertSame('prefixed', $source->fetch(new SecretName('db_password')));
    }

    #[Test]
    public function testFetchDoesNotTrimValues(): void
    {
        $this->setEnvironmentVariable('ZZTEST_UNTRIMMED', "value\n");

        $source = new EnvSecretSource();

        $this->assertSame("value\n", $source->fetch(new SecretName('zztest_untrimmed')));
    }

    #[Test]
    public function testDescribeWithoutPrefix(): void
    {
        $this->assertSame('env', (new EnvSecretSource())->describe());
    }

    #[Test]
    public function testDescribeWithPrefix(): void
    {
        $this->assertSame('env:ZZAPP_*', (new EnvSecretSource('ZZAPP_'))->describe());
    }

    #[DataProvider('validPrefixProvider')]
    #[Test]
    public function testAcceptsValidPrefixes(string $prefix): void
    {
        $source = new EnvSecretSource($prefix);

        $this->assertInstanceOf(EnvSecretSource::class, $source);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validPrefixProvider(): array
    {
        return [
            'empty'                => [''],
            'single letter'        => ['A'],
            'trailing underscore'  => ['APP_'],
            'with digits'          => ['APP2_'],
        ];
    }

    #[DataProvider('invalidPrefixProvider')]
    #[Test]
    public function testRejectsInvalidPrefixes(string $prefix): void
    {
        $this->expectException(InvalidEnvPrefixException::class);
        $this->expectExceptionMessage('Environment variable prefix contains invalid characters');

        new EnvSecretSource($prefix);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidPrefixProvider(): array
    {
        return [
            'lowercase'            => ['app_'],
            'digit first'          => ['1APP'],
            'underscore first'     => ['_APP'],
            'hyphen'               => ['APP-'],
            'newline'              => ["APP\n"],
            'equals sign'          => ['APP='],
            'non-ascii'            => ['ÄPP'],
        ];
    }

    private function setEnvironmentVariable(string $name, string $value): void
    {
        putenv(sprintf('%s=%s', $name, $value));
        $this->environmentVariables[] = $name;
    }
}
