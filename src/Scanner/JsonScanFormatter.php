<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Scanner;

use Override;
use Zappzarapp\Security\Headers\Analyzer\AnalysisResult;
use Zappzarapp\Security\Headers\Analyzer\Finding;
use Zappzarapp\Security\Headers\Analyzer\FindingSeverity;

/**
 * Machine-readable scan report for automation and CI pipelines
 */
final readonly class JsonScanFormatter implements ScanReportFormatterInterface
{
    #[Override]
    public function format(string $url, AnalysisResult $result): string
    {
        $severityCounts = [];

        foreach (FindingSeverity::cases() as $severity) {
            $severityCounts[$severity->value] = count(array_filter(
                $result->findings(),
                static fn(Finding $finding): bool => $finding->severity === $severity
            ));
        }

        $report = [
            'url'      => $url,
            'passed'   => !$result->hasHighOrAbove(),
            'findings' => array_map(
                static fn(Finding $finding): array => [
                    'header'         => $finding->header,
                    'severity'       => $finding->severity->value,
                    'message'        => $finding->message,
                    'recommendation' => $finding->recommendation,
                ],
                $result->findings()
            ),
            'summary' => [
                'total'       => $result->count(),
                'by_severity' => $severityCounts,
            ],
        ];

        return json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    }
}
