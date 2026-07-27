<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Scanner;

use Zappzarapp\Security\Headers\Analyzer\SecurityHeaderAnalyzer;
use Zappzarapp\Security\Scanner\Exception\ScanException;

/**
 * CLI command scanning a URL's response headers for security issues
 *
 * Exit codes are CI-friendly:
 *
 * - 0: scan passed (no findings of severity HIGH or above)
 * - 1: findings of severity HIGH or above
 * - 2: usage error (missing URL, unknown option)
 * - 3: scan failed (invalid URL or network error)
 *
 * ## Usage
 *
 * ```text
 * security-scan <url> [--json] [--no-color]
 * ```
 */
final readonly class ScanCommand
{
    public const int EXIT_PASSED = 0;

    public const int EXIT_FINDINGS = 1;

    public const int EXIT_USAGE = 2;

    public const int EXIT_SCAN_FAILED = 3;

    public const string USAGE = <<<'TEXT'
        Usage: security-scan <url> [options]

        Scans the URL's HTTP response headers with the zappzarapp/security
        header analyzer and reports findings by severity.

        Options:
          --json      Output the report as JSON (for automation)
          --no-color  Disable ANSI colors in text output
          -h, --help  Show this help

        Exit codes:
          0  scan passed (nothing of severity HIGH or above)
          1  findings of severity HIGH or above
          2  usage error
          3  scan failed (invalid URL or network error)
        TEXT;

    public function __construct(
        private HeaderFetcherInterface $fetcher = new StreamHeaderFetcher(),
        private SecurityHeaderAnalyzer $analyzer = new SecurityHeaderAnalyzer(),
    ) {
    }

    /**
     * Run the scan
     *
     * @param list<string> $arguments CLI arguments (without the script name)
     * @param callable(string): void $writeOutput Writer for regular output
     * @param callable(string): void $writeError Writer for error output
     *
     * @return int Exit code
     */
    public function run(array $arguments, callable $writeOutput, callable $writeError): int
    {
        $json  = false;
        $color = true;
        $url   = null;

        foreach ($arguments as $argument) {
            if ($argument === '-h' || $argument === '--help') {
                $writeOutput(self::USAGE . "\n");

                return self::EXIT_PASSED;
            }

            if ($argument === '--json') {
                $json = true;
                continue;
            }

            if ($argument === '--no-color') {
                $color = false;
                continue;
            }

            if (str_starts_with($argument, '-')) {
                $writeError(sprintf("Unknown option: %s\n\n", $argument) . self::USAGE . "\n");

                return self::EXIT_USAGE;
            }

            if ($url !== null) {
                $writeError("Only one URL can be scanned at a time.\n\n" . self::USAGE . "\n");

                return self::EXIT_USAGE;
            }

            $url = $argument;
        }

        if ($url === null) {
            $writeError(self::USAGE . "\n");

            return self::EXIT_USAGE;
        }

        try {
            $headers = $this->fetcher->fetch($url);
        } catch (ScanException $scanException) {
            $writeError($scanException->getMessage() . "\n");

            return self::EXIT_SCAN_FAILED;
        }

        $result = $this->analyzer->analyze($headers);

        $formatter = $json
            ? new JsonScanFormatter()
            : new TextScanFormatter($color);

        $writeOutput($formatter->format($url, $result));

        return $result->hasHighOrAbove() ? self::EXIT_FINDINGS : self::EXIT_PASSED;
    }
}
