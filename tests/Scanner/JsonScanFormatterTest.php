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
use Zappzarapp\Security\Scanner\JsonScanFormatter;
use Zappzarapp\Security\Scanner\ScanReportFormatterInterface;

#[CoversClass(JsonScanFormatter::class)]
#[UsesClass(AnalysisResult::class)]
#[UsesClass(Finding::class)]
final class JsonScanFormatterTest extends TestCase
{
    #[Test]
    public function testImplementsFormatterInterface(): void
    {
        /** @noinspection PhpConditionAlreadyCheckedInspection Test verifies interface implementation */
        $this->assertInstanceOf(ScanReportFormatterInterface::class, new JsonScanFormatter());
    }

    #[Test]
    public function testFormatsCleanResultAsPassed(): void
    {
        $report = (new JsonScanFormatter())->format('https://example.com', new AnalysisResult());

        $decoded = json_decode($report, true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame(
            [
                'url'      => 'https://example.com',
                'passed'   => true,
                'findings' => [],
                'summary'  => [
                    'total'       => 0,
                    'by_severity' => [
                        'critical' => 0,
                        'high'     => 0,
                        'medium'   => 0,
                        'low'      => 0,
                        'info'     => 0,
                    ],
                ],
            ],
            $decoded
        );
    }

    #[Test]
    public function testFormatsFindingsAndFailsOnHigh(): void
    {
        $result = new AnalysisResult(
            new Finding(
                'Strict-Transport-Security',
                FindingSeverity::HIGH,
                'Header is missing',
                'Add Strict-Transport-Security'
            ),
            new Finding('X-Frame-Options', FindingSeverity::MEDIUM, 'Header is missing', 'Add X-Frame-Options'),
            new Finding('Referrer-Policy', FindingSeverity::MEDIUM, 'Header is missing', 'Add Referrer-Policy'),
        );

        $report = (new JsonScanFormatter())->format('https://example.com', $result);

        $this->assertStringStartsWith('{', $report);
        $this->assertStringEndsWith("}\n", $report);

        $decoded = json_decode($report, true, 512, JSON_THROW_ON_ERROR);

        $this->assertFalse($decoded['passed']);
        $this->assertSame(3, $decoded['summary']['total']);
        $this->assertSame(0, $decoded['summary']['by_severity']['critical']);
        $this->assertSame(1, $decoded['summary']['by_severity']['high']);
        $this->assertSame(2, $decoded['summary']['by_severity']['medium']);
        $this->assertSame(
            [
                'header'         => 'Strict-Transport-Security',
                'severity'       => 'high',
                'message'        => 'Header is missing',
                'recommendation' => 'Add Strict-Transport-Security',
            ],
            $decoded['findings'][0]
        );
    }

    #[Test]
    public function testMediumFindingsAlonePass(): void
    {
        $result = new AnalysisResult(
            new Finding('X-Frame-Options', FindingSeverity::MEDIUM, 'Header is missing', 'Add X-Frame-Options'),
        );

        $report = (new JsonScanFormatter())->format('https://example.com', $result);

        $decoded = json_decode($report, true, 512, JSON_THROW_ON_ERROR);

        $this->assertTrue($decoded['passed']);
    }

    #[Test]
    public function testDoesNotEscapeSlashesInUrl(): void
    {
        $report = (new JsonScanFormatter())->format('https://example.com/path', new AnalysisResult());

        $this->assertStringContainsString('"https://example.com/path"', $report);
    }
}
