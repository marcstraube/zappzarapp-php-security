<?php

/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Report;

use Closure;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Exception\CspReportException;
use Zappzarapp\Security\Csp\Report\CspViolationReport;
use Zappzarapp\Security\Csp\Report\ReportDisposition;
use Zappzarapp\Security\Csp\Report\ViolationSource;

#[CoversClass(CspViolationReport::class)]
#[CoversClass(CspReportException::class)]
#[UsesClass(ReportDisposition::class)]
#[UsesClass(ViolationSource::class)]
final class CspViolationReportTest extends TestCase
{
    #[Test]
    public function testDefaultsEverythingBeyondTheRequiredFields(): void
    {
        $report = new CspViolationReport('https://example.com/', 'script-src', 'script-src');

        $this->assertSame('', $report->blockedUri);
        $this->assertSame('', $report->originalPolicy);
        $this->assertSame('', $report->referrer);
        $this->assertNull($report->disposition);
        $this->assertNull($report->statusCode);
        $this->assertSame('', $report->scriptSample);
        $this->assertSame('', $report->source->file);
        $this->assertSame('', $report->userAgent);
    }

    #[Test]
    public function testEnforcedViolationWasBlocked(): void
    {
        $this->assertTrue($this->reportWithDisposition(ReportDisposition::ENFORCE)->wasBlocked());
    }

    #[Test]
    public function testReportOnlyViolationWasNotBlocked(): void
    {
        $this->assertFalse($this->reportWithDisposition(ReportDisposition::REPORT)->wasBlocked());
    }

    #[Test]
    public function testViolationWithoutDispositionWasNotBlocked(): void
    {
        $this->assertFalse($this->reportWithDisposition(null)->wasBlocked());
    }

    #[Test]
    public function testLogContextCarriesEveryReportedField(): void
    {
        $report = new CspViolationReport(
            documentUri: 'https://example.com/signup',
            violatedDirective: 'script-src https://cdn.example.com',
            effectiveDirective: 'script-src',
            blockedUri: 'https://evil.example.com/payload.js',
            originalPolicy: "default-src 'self'",
            referrer: 'https://example.com/',
            disposition: ReportDisposition::ENFORCE,
            statusCode: 200,
            scriptSample: 'alert(1)',
            source: new ViolationSource('https://example.com/app.js', 12, 5),
            userAgent: 'Mozilla/5.0',
        );

        $this->assertSame([
            'document_uri'        => 'https://example.com/signup',
            'violated_directive'  => 'script-src https://cdn.example.com',
            'effective_directive' => 'script-src',
            'blocked_uri'         => 'https://evil.example.com/payload.js',
            'original_policy'     => "default-src 'self'",
            'referrer'            => 'https://example.com/',
            'disposition'         => 'enforce',
            'status_code'         => 200,
            'script_sample'       => 'alert(1)',
            'source_file'         => 'https://example.com/app.js',
            'line_number'         => 12,
            'column_number'       => 5,
            'user_agent'          => 'Mozilla/5.0',
        ], $report->toLogContext());
    }

    #[Test]
    public function testLogContextReportsUnreportedFieldsAsNull(): void
    {
        $report = new CspViolationReport('https://example.com/', 'script-src', 'script-src');

        $this->assertSame([
            'document_uri'        => 'https://example.com/',
            'violated_directive'  => 'script-src',
            'effective_directive' => 'script-src',
            'blocked_uri'         => null,
            'original_policy'     => null,
            'referrer'            => null,
            'disposition'         => null,
            'status_code'         => null,
            'script_sample'       => null,
            'source_file'         => null,
            'line_number'         => null,
            'column_number'       => null,
            'user_agent'          => null,
        ], $report->toLogContext());
    }

    /**
     * @return iterable<string, array{Closure(): CspViolationReport, string}>
     */
    public static function missingRequiredFieldProvider(): iterable
    {
        yield 'document-uri' => [
            static fn (): CspViolationReport => new CspViolationReport('', 'script-src', 'script-src'),
            'missing the required field: document-uri',
        ];

        yield 'violated-directive' => [
            static fn (): CspViolationReport => new CspViolationReport('https://example.com/', '', 'script-src'),
            'missing the required field: violated-directive',
        ];

        yield 'effective-directive' => [
            static fn (): CspViolationReport => new CspViolationReport('https://example.com/', 'script-src', ''),
            'missing the required field: effective-directive',
        ];
    }

    /**
     * @param Closure(): CspViolationReport $construct
     */
    #[DataProvider('missingRequiredFieldProvider')]
    #[Test]
    public function testRejectsMissingRequiredFields(Closure $construct, string $message): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage($message);

        $construct();
    }

    /**
     * @return iterable<string, array{Closure(): CspViolationReport, string}>
     */
    public static function controlCharacterProvider(): iterable
    {
        yield 'document-uri' => [
            static fn (): CspViolationReport => new CspViolationReport("https://example.com/\n", 'script-src', 'script-src'),
            'document-uri',
        ];

        yield 'violated-directive' => [
            static fn (): CspViolationReport => new CspViolationReport('https://example.com/', "script-src\r", 'script-src'),
            'violated-directive',
        ];

        yield 'effective-directive' => [
            static fn (): CspViolationReport => new CspViolationReport('https://example.com/', 'script-src', "script-src\x00"),
            'effective-directive',
        ];

        yield 'blocked-uri' => [
            static fn (): CspViolationReport => new CspViolationReport(
                'https://example.com/',
                'script-src',
                'script-src',
                blockedUri: "https://evil.example.com/\nfaked log line",
            ),
            'blocked-uri',
        ];

        yield 'original-policy' => [
            static fn (): CspViolationReport => new CspViolationReport(
                'https://example.com/',
                'script-src',
                'script-src',
                originalPolicy: "default-src 'self'\n",
            ),
            'original-policy',
        ];

        yield 'referrer' => [
            static fn (): CspViolationReport => new CspViolationReport(
                'https://example.com/',
                'script-src',
                'script-src',
                referrer: "https://example.com/\x7F",
            ),
            'referrer',
        ];

        yield 'script-sample' => [
            static fn (): CspViolationReport => new CspViolationReport(
                'https://example.com/',
                'script-src',
                'script-src',
                scriptSample: "alert(1)\n",
            ),
            'script-sample',
        ];

        yield 'user-agent' => [
            static fn (): CspViolationReport => new CspViolationReport(
                'https://example.com/',
                'script-src',
                'script-src',
                userAgent: "Mozilla/5.0\r\n",
            ),
            'user-agent',
        ];

        yield 'unicode line separator' => [
            static fn (): CspViolationReport => new CspViolationReport(
                'https://example.com/',
                'script-src',
                'script-src',
                blockedUri: "https://evil.example.com/\u{2028}forged line",
            ),
            'blocked-uri',
        ];
    }

    /**
     * @param Closure(): CspViolationReport $construct
     */
    #[DataProvider('controlCharacterProvider')]
    #[Test]
    public function testRejectsControlCharactersInEveryField(Closure $construct, string $field): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('control characters: ' . $field);

        $construct();
    }

    /**
     * Each entry builds a report from a single field value and reads that
     * field back, so the same provider drives both the accepted and the
     * rejected boundary.
     *
     * @return iterable<string, array{int, Closure(string): string, string}>
     */
    public static function lengthLimitProvider(): iterable
    {
        yield 'document-uri' => [
            CspViolationReport::MAX_URI_LENGTH,
            static fn (string $value): string => (new CspViolationReport($value, 'script-src', 'script-src'))->documentUri,
            'document-uri',
        ];

        yield 'violated-directive' => [
            CspViolationReport::MAX_DIRECTIVE_LENGTH,
            static fn (string $value): string => (new CspViolationReport('https://example.com/', $value, 'script-src'))->violatedDirective,
            'violated-directive',
        ];

        yield 'original-policy' => [
            CspViolationReport::MAX_POLICY_LENGTH,
            static fn (string $value): string => (new CspViolationReport(
                'https://example.com/',
                'script-src',
                'script-src',
                originalPolicy: $value,
            ))->originalPolicy,
            'original-policy',
        ];

        yield 'script-sample' => [
            CspViolationReport::MAX_SAMPLE_LENGTH,
            static fn (string $value): string => (new CspViolationReport(
                'https://example.com/',
                'script-src',
                'script-src',
                scriptSample: $value,
            ))->scriptSample,
            'script-sample',
        ];

        yield 'user-agent' => [
            CspViolationReport::MAX_USER_AGENT_LENGTH,
            static fn (string $value): string => (new CspViolationReport(
                'https://example.com/',
                'script-src',
                'script-src',
                userAgent: $value,
            ))->userAgent,
            'user-agent',
        ];
    }

    /**
     * @param Closure(string): string $roundTrip
     */
    #[DataProvider('lengthLimitProvider')]
    #[Test]
    public function testAcceptsFieldsAtTheLengthLimit(int $limit, Closure $roundTrip, string $field): void
    {
        $value = str_repeat('a', $limit);

        $this->assertSame($value, $roundTrip($value), sprintf('%s must be accepted at exactly %d characters', $field, $limit));
    }

    /**
     * @param Closure(string): string $roundTrip
     */
    #[DataProvider('lengthLimitProvider')]
    #[Test]
    public function testRejectsFieldsBeyondTheLengthLimit(int $limit, Closure $roundTrip, string $field): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage(sprintf('%s exceeds the maximum of %d characters', $field, $limit));

        $roundTrip(str_repeat('a', $limit + 1));
    }

    #[Test]
    public function testRejectsMalformedUtf8BeforeCheckingForControlCharacters(): void
    {
        // A Unicode pattern does not match at all against malformed UTF-8,
        // so without the encoding check the newline would slip through
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('not valid UTF-8: blocked-uri');

        new CspViolationReport(
            'https://example.com/',
            'script-src',
            'script-src',
            blockedUri: "https://evil.example.com/\xFF\xFE\nforged line",
        );
    }

    #[Test]
    public function testMeasuresFieldLengthsInCharactersNotBytes(): void
    {
        // Twice the limit in bytes, exactly the limit in characters
        $sample = str_repeat('ä', CspViolationReport::MAX_SAMPLE_LENGTH);

        $report = new CspViolationReport(
            'https://example.com/',
            'script-src',
            'script-src',
            scriptSample: $sample,
        );

        $this->assertSame($sample, $report->scriptSample);
    }

    #[Test]
    public function testAcceptsZeroAsAStatusCode(): void
    {
        $report = new CspViolationReport('https://example.com/', 'script-src', 'script-src', statusCode: 0);

        $this->assertSame(0, $report->statusCode);
    }

    #[Test]
    public function testRejectsANegativeStatusCode(): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('must not be negative: status-code');

        new CspViolationReport('https://example.com/', 'script-src', 'script-src', statusCode: -1);
    }

    private function reportWithDisposition(?ReportDisposition $disposition): CspViolationReport
    {
        return new CspViolationReport(
            'https://example.com/',
            'script-src',
            'script-src',
            disposition: $disposition,
        );
    }
}
