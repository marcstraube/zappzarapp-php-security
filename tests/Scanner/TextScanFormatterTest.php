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
use Zappzarapp\Security\Headers\Analyzer\FindingSeverity;
use Zappzarapp\Security\Scanner\ScanReportFormatterInterface;
use Zappzarapp\Security\Scanner\TextScanFormatter;

#[CoversClass(TextScanFormatter::class)]
#[UsesClass(AnalysisResult::class)]
#[UsesClass(Finding::class)]
final class TextScanFormatterTest extends TestCase
{
    #[Test]
    public function testImplementsFormatterInterface(): void
    {
        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(ScanReportFormatterInterface::class, new TextScanFormatter());
    }

    #[Test]
    public function testFormatsCleanResult(): void
    {
        $report = (new TextScanFormatter())->format('https://example.com', new AnalysisResult());

        $this->assertSame(
            "Security header scan for https://example.com\n"
            . "\n"
            . "No findings - all analyzed security headers look good.\n",
            $report
        );
    }

    #[Test]
    public function testFormatsFindingsWithoutColors(): void
    {
        $result = new AnalysisResult(
            new Finding(
                'Strict-Transport-Security',
                FindingSeverity::HIGH,
                'Header is missing',
                'Add Strict-Transport-Security with max-age >= 31536000'
            ),
            new Finding(
                'X-Frame-Options',
                FindingSeverity::MEDIUM,
                'Header is missing',
                'Add X-Frame-Options: DENY'
            ),
        );

        $report = (new TextScanFormatter(colors: false))->format('https://example.com', $result);

        $this->assertSame(
            "Security header scan for https://example.com\n"
            . "\n"
            . "[HIGH] Strict-Transport-Security: Header is missing\n"
            . "  fix: Add Strict-Transport-Security with max-age >= 31536000\n"
            . "[MEDIUM] X-Frame-Options: Header is missing\n"
            . "  fix: Add X-Frame-Options: DENY\n"
            . "\n"
            . "2 finding(s): 1 high, 1 medium\n",
            $report
        );
    }

    #[Test]
    public function testFormatsFindingsWithColors(): void
    {
        $result = new AnalysisResult(
            new Finding('Content-Security-Policy', FindingSeverity::CRITICAL, 'Uses unsafe-inline', 'Remove unsafe-inline'),
        );

        $report = (new TextScanFormatter())->format('https://example.com', $result);

        $this->assertStringContainsString("\e[1;31m[CRITICAL]\e[0m Content-Security-Policy", $report);
    }

    #[Test]
    public function testStripsControlBytesFromServerControlledFields(): void
    {
        $result = new AnalysisResult(
            new Finding(
                "X-Frame\x1b[2J-Options",
                FindingSeverity::HIGH,
                "Header is\x1b[1A missing",
                "Add X-Frame-Options:\x07 DENY"
            ),
        );

        $report = (new TextScanFormatter(colors: false))->format('https://example.com', $result);

        $this->assertStringNotContainsString("\x1b", $report);
        $this->assertStringNotContainsString("\x07", $report);
        $this->assertStringContainsString('[HIGH] X-Frame[2J-Options: Header is[1A missing', $report);
        $this->assertStringContainsString('  fix: Add X-Frame-Options: DENY', $report);
    }

    #[Test]
    public function testStripsControlBytesFromUrl(): void
    {
        $report = (new TextScanFormatter(colors: false))->format(
            "https://example.com\x1b[2J",
            new AnalysisResult()
        );

        $this->assertStringNotContainsString("\x1b", $report);
        $this->assertStringContainsString('Security header scan for https://example.com[2J', $report);
    }

    #[Test]
    public function testPreservesOwnColorCodesWhileStrippingServerData(): void
    {
        $result = new AnalysisResult(
            new Finding("Header\x1b[31m", FindingSeverity::CRITICAL, 'msg', 'rec'),
        );

        $report = (new TextScanFormatter())->format('https://example.com', $result);

        // The formatter's own color codes survive, the injected one is gone
        $this->assertStringContainsString("\e[1;31m[CRITICAL]\e[0m Header[31m: msg", $report);
    }

    #[Test]
    public function testSummaryCountsEverySeverity(): void
    {
        $result = new AnalysisResult(
            new Finding('A', FindingSeverity::CRITICAL, 'm', 'r'),
            new Finding('B', FindingSeverity::HIGH, 'm', 'r'),
            new Finding('C', FindingSeverity::MEDIUM, 'm', 'r'),
            new Finding('D', FindingSeverity::LOW, 'm', 'r'),
            new Finding('E', FindingSeverity::INFO, 'm', 'r'),
        );

        $report = (new TextScanFormatter(colors: false))->format('https://example.com', $result);

        $this->assertStringContainsString(
            '5 finding(s): 1 critical, 1 high, 1 medium, 1 low, 1 info',
            $report
        );
    }
}
