<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Scanner;

use Override;
use Zappzarapp\Security\Headers\Analyzer\AnalysisResult;
use Zappzarapp\Security\Headers\Analyzer\Finding;
use Zappzarapp\Security\Headers\Analyzer\FindingSeverity;

/**
 * Human-readable scan report with optional ANSI colors
 */
final readonly class TextScanFormatter implements ScanReportFormatterInterface
{
    private const string ANSI_RESET = "\e[0m";

    /**
     * ANSI style per severity
     *
     * @var array<string, string>
     */
    private const array SEVERITY_STYLES = [
        'critical' => "\e[1;31m", // bold red
        'high'     => "\e[31m",   // red
        'medium'   => "\e[33m",   // yellow
        'low'      => "\e[36m",   // cyan
        'info'     => "\e[90m",   // gray
    ];

    public function __construct(
        private bool $colors = true,
    ) {
    }

    #[Override]
    public function format(string $url, AnalysisResult $result): string
    {
        $lines   = [];
        $lines[] = sprintf('Security header scan for %s', $url);
        $lines[] = '';

        if ($result->isClean()) {
            $lines[] = 'No findings - all analyzed security headers look good.';

            return implode("\n", $lines) . "\n";
        }

        foreach ($result->findings() as $finding) {
            $lines[] = $this->formatFinding($finding);
            $lines[] = sprintf('  fix: %s', $finding->recommendation);
        }

        $lines[] = '';
        $lines[] = $this->formatSummary($result);

        return implode("\n", $lines) . "\n";
    }

    private function formatFinding(Finding $finding): string
    {
        $label = sprintf('[%s]', strtoupper($finding->severity->value));

        if ($this->colors) {
            $label = self::SEVERITY_STYLES[$finding->severity->value] . $label . self::ANSI_RESET;
        }

        return sprintf('%s %s: %s', $label, $finding->header, $finding->message);
    }

    private function formatSummary(AnalysisResult $result): string
    {
        $counts = [];

        foreach (FindingSeverity::cases() as $severity) {
            $count = count(array_filter(
                $result->findings(),
                static fn(Finding $finding): bool => $finding->severity === $severity
            ));

            if ($count > 0) {
                $counts[] = sprintf('%d %s', $count, $severity->value);
            }
        }

        return sprintf('%d finding(s): %s', $result->count(), implode(', ', $counts));
    }
}
