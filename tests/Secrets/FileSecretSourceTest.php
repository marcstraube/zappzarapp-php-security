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
use Zappzarapp\Security\Secrets\Exception\SecretLoadException;
use Zappzarapp\Security\Secrets\FileSecretSource;
use Zappzarapp\Security\Secrets\SecretName;

#[CoversClass(FileSecretSource::class)]
#[CoversClass(SecretLoadException::class)]
#[UsesClass(SecretName::class)]
final class FileSecretSourceTest extends TestCase
{
    private string $secretsDir;

    #[Override]
    protected function setUp(): void
    {
        $this->secretsDir = sys_get_temp_dir() . '/zz-secrets-test-' . bin2hex(random_bytes(6));
        mkdir($this->secretsDir, 0o700);
    }

    #[Override]
    protected function tearDown(): void
    {
        $files = glob($this->secretsDir . '/*');
        foreach ($files === false ? [] : $files as $file) {
            chmod($file, 0o600);
            unlink($file);
        }

        rmdir($this->secretsDir);
    }

    #[Test]
    public function testFetchReadsSecretFile(): void
    {
        $this->writeSecret('db_password', 's3cr3t');

        $source = new FileSecretSource($this->secretsDir);

        $this->assertSame('s3cr3t', $source->fetch(new SecretName('db_password')));
    }

    #[Test]
    public function testFetchFallsBackToTxtExtension(): void
    {
        $this->writeSecret('db_password.txt', 'from-txt');

        $source = new FileSecretSource($this->secretsDir);

        $this->assertSame('from-txt', $source->fetch(new SecretName('db_password')));
    }

    #[Test]
    public function testFetchPrefersExactNameOverTxtExtension(): void
    {
        $this->writeSecret('db_password', 'exact');
        $this->writeSecret('db_password.txt', 'txt-fallback');

        $source = new FileSecretSource($this->secretsDir);

        $this->assertSame('exact', $source->fetch(new SecretName('db_password')));
    }

    #[Test]
    public function testFetchReturnsNullForMissingSecret(): void
    {
        $source = new FileSecretSource($this->secretsDir);

        $this->assertNull($source->fetch(new SecretName('missing')));
    }

    #[Test]
    public function testFetchReturnsNullForMissingBaseDirectory(): void
    {
        $source = new FileSecretSource($this->secretsDir . '/does-not-exist');

        $this->assertNull($source->fetch(new SecretName('db_password')));
    }

    #[DataProvider('newlineTrimmingProvider')]
    #[Test]
    public function testFetchTrimsOnlyOneTrailingNewline(string $fileContent, string $expected): void
    {
        $this->writeSecret('secret', $fileContent);

        $source = new FileSecretSource($this->secretsDir);

        $this->assertSame($expected, $source->fetch(new SecretName('secret')));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function newlineTrimmingProvider(): array
    {
        return [
            'trailing lf'          => ["value\n", 'value'],
            'trailing crlf'        => ["value\r\n", 'value'],
            'double trailing lf'   => ["value\n\n", "value\n"],
            'lone cr kept'         => ["value\r", "value\r"],
            'no trailing newline'  => ['value', 'value'],
            'inner newline kept'   => ["multi\nline\n", "multi\nline"],
            'whitespace kept'      => ["  value  \n", '  value  '],
            'only newline'         => ["\n", ''],
        ];
    }

    #[Test]
    public function testFetchReturnsEmptyStringForEmptyFile(): void
    {
        $this->writeSecret('empty', '');

        $source = new FileSecretSource($this->secretsDir);

        $this->assertSame('', $source->fetch(new SecretName('empty')));
    }

    #[Test]
    public function testFetchThrowsForUnreadableFile(): void
    {
        $path = $this->writeSecret('locked', 's3cr3t');
        chmod($path, 0o000);

        if (is_readable($path)) {
            $this->markTestSkipped('File remains readable (running with elevated privileges)');
        }

        $source = new FileSecretSource($this->secretsDir);

        $this->expectException(SecretLoadException::class);
        $this->expectExceptionMessage(
            sprintf('Secret file "%s" exists but cannot be read (check file permissions)', $path)
        );

        $source->fetch(new SecretName('locked'));
    }

    #[Test]
    public function testDescribeIncludesBasePath(): void
    {
        $source = new FileSecretSource('/etc/app/secrets');

        $this->assertSame('file:/etc/app/secrets', $source->describe());
    }

    #[Test]
    public function testDescribeNormalizesTrailingSlash(): void
    {
        $source = new FileSecretSource('/etc/app/secrets/');

        $this->assertSame('file:/etc/app/secrets', $source->describe());
    }

    #[Test]
    public function testDefaultBasePathIsDockerSecretsMount(): void
    {
        $this->assertSame('/run/secrets', FileSecretSource::DEFAULT_BASE_PATH);
        $this->assertSame('file:/run/secrets', (new FileSecretSource())->describe());
    }

    private function writeSecret(string $filename, string $content): string
    {
        $path = $this->secretsDir . '/' . $filename;
        file_put_contents($path, $content);

        return $path;
    }
}
