<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Scanner;

use Zappzarapp\Security\Headers\Analyzer\AnalysisResult;

/**
 * Formats a scan result for CLI output
 */
interface ScanReportFormatterInterface
{
    /**
     * Format the analysis result of a scanned URL
     */
    public function format(string $url, AnalysisResult $result): string;
}
