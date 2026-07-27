<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Scanner;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Headers\Analyzer\AnalysisResult;
use Zappzarapp\Security\Headers\Analyzer\Finding;
use Zappzarapp\Security\Headers\Analyzer\SecurityHeaderAnalyzer;
use Zappzarapp\Security\Scanner\Exception\ScanException;
use Zappzarapp\Security\Scanner\HeaderFetcherInterface;
use Zappzarapp\Security\Scanner\JsonScanFormatter;
use Zappzarapp\Security\Scanner\ScanCommand;
use Zappzarapp\Security\Scanner\TextScanFormatter;

#[CoversClass(ScanCommand::class)]
#[UsesClass(AnalysisResult::class)]
#[UsesClass(Finding::class)]
#[UsesClass(SecurityHeaderAnalyzer::class)]
#[UsesClass(JsonScanFormatter::class)]
#[UsesClass(TextScanFormatter::class)]
#[UsesClass(ScanException::class)]
final class ScanCommandTest extends TestCase
{
    /**
     * Headers that pass the analyzer without findings
     *
     * @var array<string, string>
     */
    private const array SECURE_HEADERS = [
        'Strict-Transport-Security'    => 'max-age=63072000; includeSubDomains; preload',
        'Content-Security-Policy'      => "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        'X-Frame-Options'              => 'DENY',
        'X-Content-Type-Options'       => 'nosniff',
        'Referrer-Policy'              => 'strict-origin-when-cross-origin',
        'Permissions-Policy'           => 'geolocation=(), camera=()',
        'Cross-Origin-Opener-Policy'   => 'same-origin',
        'Cross-Origin-Embedder-Policy' => 'require-corp',
        'Cross-Origin-Resource-Policy' => 'same-origin',
    ];

    private string $output = '';

    private string $errors = '';

    protected function setUp(): void
    {
        $this->output = '';
        $this->errors = '';
    }

    #[Test]
    public function testHelpPrintsUsage(): void
    {
        $exitCode = $this->runCommand(['--help'], $this->fetcherWith([]));

        $this->assertSame(ScanCommand::EXIT_PASSED, $exitCode);
        $this->assertSame(ScanCommand::USAGE . "\n", $this->output);
        $this->assertSame('', $this->errors);
    }

    #[Test]
    public function testShortHelpPrintsUsage(): void
    {
        $exitCode = $this->runCommand(['-h'], $this->fetcherWith([]));

        $this->assertSame(ScanCommand::EXIT_PASSED, $exitCode);
        $this->assertSame(ScanCommand::USAGE . "\n", $this->output);
    }

    #[Test]
    public function testMissingUrlIsUsageError(): void
    {
        $exitCode = $this->runCommand([], $this->fetcherWith([]));

        $this->assertSame(ScanCommand::EXIT_USAGE, $exitCode);
        $this->assertSame(ScanCommand::USAGE . "\n", $this->errors);
        $this->assertSame('', $this->output);
    }

    #[Test]
    public function testUnknownOptionIsUsageError(): void
    {
        $exitCode = $this->runCommand(['--verbose', 'https://example.com'], $this->fetcherWith([]));

        $this->assertSame(ScanCommand::EXIT_USAGE, $exitCode);
        $this->assertSame("Unknown option: --verbose\n\n" . ScanCommand::USAGE . "\n", $this->errors);
        $this->assertSame('', $this->output);
    }

    #[Test]
    public function testMultipleUrlsAreUsageError(): void
    {
        $exitCode = $this->runCommand(
            ['https://example.com', 'https://example.org'],
            $this->fetcherWith([])
        );

        $this->assertSame(ScanCommand::EXIT_USAGE, $exitCode);
        $this->assertSame(
            "Only one URL can be scanned at a time.\n\n" . ScanCommand::USAGE . "\n",
            $this->errors
        );
    }

    #[Test]
    public function testFetchFailureExitsWithScanFailed(): void
    {
        $exitCode = $this->runCommand(['https://example.com'], $this->failingFetcher());

        $this->assertSame(ScanCommand::EXIT_SCAN_FAILED, $exitCode);
        $this->assertSame(
            'Could not fetch response headers from "https://example.com" '
            . "(network error or unreachable host)\n",
            $this->errors
        );
        $this->assertSame('', $this->output);
    }

    #[Test]
    public function testSecureHeadersPass(): void
    {
        $exitCode = $this->runCommand(['https://example.com'], $this->fetcherWith(self::SECURE_HEADERS));

        $this->assertSame(ScanCommand::EXIT_PASSED, $exitCode);
        $this->assertStringContainsString('No findings', $this->output);
    }

    #[Test]
    public function testMissingHeadersFailWithFindingsExitCode(): void
    {
        $exitCode = $this->runCommand(['--no-color', 'https://example.com'], $this->fetcherWith([]));

        $this->assertSame(ScanCommand::EXIT_FINDINGS, $exitCode);
        $this->assertStringContainsString('[HIGH] Strict-Transport-Security', $this->output);
    }

    #[Test]
    public function testColorsAreEnabledByDefault(): void
    {
        $this->runCommand(['https://example.com'], $this->fetcherWith([]));

        $this->assertStringContainsString("\e[", $this->output);
    }

    #[Test]
    public function testNoColorDisablesAnsiCodes(): void
    {
        $this->runCommand(['--no-color', 'https://example.com'], $this->fetcherWith([]));

        $this->assertStringNotContainsString("\e[", $this->output);
    }

    #[Test]
    public function testJsonOutput(): void
    {
        $exitCode = $this->runCommand(['--json', 'https://example.com'], $this->fetcherWith([]));

        $decoded = json_decode($this->output, true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame(ScanCommand::EXIT_FINDINGS, $exitCode);
        $this->assertIsArray($decoded);
        $this->assertFalse($decoded['passed']);
        $this->assertSame('https://example.com', $decoded['url']);
    }

    #[Test]
    public function testJsonOutputForPassingScan(): void
    {
        $exitCode = $this->runCommand(['--json', 'https://example.com'], $this->fetcherWith(self::SECURE_HEADERS));

        $decoded = json_decode($this->output, true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame(ScanCommand::EXIT_PASSED, $exitCode);
        $this->assertIsArray($decoded);
        $this->assertTrue($decoded['passed']);
    }

    /**
     * @param list<string> $arguments
     */
    private function runCommand(array $arguments, HeaderFetcherInterface $fetcher): int
    {
        $command = new ScanCommand($fetcher);

        return $command->run(
            $arguments,
            function (string $text): void {
                $this->output .= $text;
            },
            function (string $text): void {
                $this->errors .= $text;
            },
        );
    }

    /**
     * @param array<string, string> $headers
     */
    private function fetcherWith(array $headers): HeaderFetcherInterface
    {
        return new class($headers) implements HeaderFetcherInterface {
            /**
             * @param array<string, string> $headers
             */
            public function __construct(private readonly array $headers)
            {
            }

            public function fetch(string $url): array
            {
                return $this->headers;
            }
        };
    }

    private function failingFetcher(): HeaderFetcherInterface
    {
        return new class implements HeaderFetcherInterface {
            public function fetch(string $url): array
            {
                throw ScanException::fetchFailed($url);
            }
        };
    }
}
