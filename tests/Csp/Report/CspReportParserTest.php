<?php

/** @noinspection PhpUnhandledExceptionInspection PHPUnit reports escaped exceptions as test errors; test methods omit @throws by convention */
/** @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax */

declare(strict_types=1);

namespace Zappzarapp\Security\Tests\Csp\Report;

use JsonException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Zappzarapp\Security\Csp\Exception\CspReportException;
use Zappzarapp\Security\Csp\Report\CspReportParser;
use Zappzarapp\Security\Csp\Report\CspViolationReport;
use Zappzarapp\Security\Csp\Report\ReportDisposition;
use Zappzarapp\Security\Csp\Report\ViolationSource;

#[CoversClass(CspReportParser::class)]
#[CoversClass(CspReportException::class)]
#[UsesClass(CspViolationReport::class)]
#[UsesClass(ReportDisposition::class)]
#[UsesClass(ViolationSource::class)]
final class CspReportParserTest extends TestCase
{
    private CspReportParser $parser;

    protected function setUp(): void
    {
        $this->parser = new CspReportParser();
    }

    // ---------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------

    #[Test]
    public function testDefaultsTo16KibOfPayload(): void
    {
        $this->assertSame(16_384, CspReportParser::DEFAULT_MAX_PAYLOAD_BYTES);
        $this->assertSame(CspReportParser::DEFAULT_MAX_PAYLOAD_BYTES, $this->parser->maxPayloadBytes);
    }

    #[Test]
    public function testAcceptsACustomPayloadLimit(): void
    {
        $this->assertSame(64, (new CspReportParser(64))->maxPayloadBytes);
    }

    #[Test]
    public function testAcceptsAPayloadLimitOfOneByte(): void
    {
        $this->assertSame(1, (new CspReportParser(1))->maxPayloadBytes);
    }

    #[Test]
    public function testRejectsAPayloadLimitBelowOneByte(): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('at least 1 byte, got 0');

        new CspReportParser(0);
    }

    // ---------------------------------------------------------------
    // Payload size
    // ---------------------------------------------------------------

    #[Test]
    public function testAcceptsAPayloadAtTheSizeLimit(): void
    {
        $payload = self::legacyPayloadOfSize(CspReportParser::DEFAULT_MAX_PAYLOAD_BYTES);

        $this->assertCount(1, $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_LEGACY));
    }

    #[Test]
    public function testRejectsAPayloadBeyondTheSizeLimit(): void
    {
        $payload = self::legacyPayloadOfSize(CspReportParser::DEFAULT_MAX_PAYLOAD_BYTES + 1);

        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('exceeds the maximum of 16384 bytes');

        $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_LEGACY);
    }

    #[Test]
    public function testTheSizeLimitIsCheckedBeforeTheContentType(): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('exceeds the maximum of 8 bytes');

        (new CspReportParser(8))->parse('{"a": "bbbbbbbbbb"}', 'text/plain');
    }

    #[Test]
    public function testAnUnreadableBodyRejectsWithoutNamingTheStreamError(): void
    {
        // Raised by CspReportHandler when a PSR-7 stream fails mid-read
        $this->assertSame(
            'CSP report body could not be read',
            CspReportException::unreadableBody()->getMessage()
        );
    }

    // ---------------------------------------------------------------
    // Content type
    // ---------------------------------------------------------------

    /**
     * @return iterable<string, array{string}>
     */
    public static function acceptedContentTypeProvider(): iterable
    {
        yield 'legacy' => ['application/csp-report'];
        yield 'legacy with charset' => ['application/csp-report; charset=utf-8'];
        yield 'legacy uppercase' => ['APPLICATION/CSP-REPORT'];
        yield 'legacy padded' => ['  application/csp-report  '];
    }

    #[DataProvider('acceptedContentTypeProvider')]
    #[Test]
    public function testAcceptsTheLegacyContentTypeWithParameters(string $contentType): void
    {
        $reports = $this->parser->parse(self::legacyPayload(), $contentType);

        $this->assertSame('https://example.com/signup', $reports[0]->documentUri);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedContentTypeProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'plain json' => ['application/json'];
        yield 'form encoded' => ['application/x-www-form-urlencoded'];
        yield 'prefix only' => ['application/csp'];
        yield 'suffix' => ['application/csp-report-extra'];
    }

    #[DataProvider('rejectedContentTypeProvider')]
    #[Test]
    public function testRejectsAnUnsupportedContentType(string $contentType): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('unsupported Content-Type');

        $this->parser->parse(self::legacyPayload(), $contentType);
    }

    #[Test]
    public function testTheRejectionNeverEchoesTheContentType(): void
    {
        try {
            $this->parser->parse(self::legacyPayload(), 'text/x-attacker-controlled');
            $this->fail('Expected the report to be rejected');
        } catch (CspReportException $exception) {
            $this->assertStringNotContainsString('attacker', $exception->getMessage());
        }
    }

    // ---------------------------------------------------------------
    // Envelope
    // ---------------------------------------------------------------

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function malformedLegacyProvider(): iterable
    {
        yield 'not json' => ['not json at all', 'not valid JSON'];
        yield 'empty body' => ['', 'not valid JSON'];
        yield 'truncated' => ['{"csp-report": {', 'not valid JSON'];
        yield 'top level string' => ['"a string"', 'unexpected structure'];
        yield 'top level number' => ['42', 'unexpected structure'];
        yield 'top level null' => ['null', 'unexpected structure'];
        yield 'wrapper missing' => ['{"report": {}}', 'unexpected structure'];
        yield 'wrapper not an object' => ['{"csp-report": "nope"}', 'unexpected structure'];
    }

    #[DataProvider('malformedLegacyProvider')]
    #[Test]
    public function testRejectsAMalformedLegacyPayload(string $payload, string $message): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage($message);

        $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_LEGACY);
    }

    #[Test]
    public function testAcceptsNestingUpToTheDepthLimit(): void
    {
        $payload = self::legacyWithExtra(self::nested(5));

        $this->assertCount(1, $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_LEGACY));
    }

    #[Test]
    public function testRejectsNestingBeyondTheDepthLimit(): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('not valid JSON');

        $this->parser->parse(self::legacyWithExtra(self::nested(6)), CspReportParser::CONTENT_TYPE_LEGACY);
    }

    // ---------------------------------------------------------------
    // Legacy report bodies
    // ---------------------------------------------------------------

    #[Test]
    public function testParsesACompleteLegacyReport(): void
    {
        $reports = $this->parser->parse(self::legacyPayload(), CspReportParser::CONTENT_TYPE_LEGACY);

        $this->assertCount(1, $reports);

        $report = $reports[0];
        $this->assertSame('https://example.com/signup', $report->documentUri);
        $this->assertSame('script-src https://cdn.example.com', $report->violatedDirective);
        $this->assertSame('script-src-elem', $report->effectiveDirective);
        $this->assertSame('https://evil.example.com/payload.js', $report->blockedUri);
        $this->assertSame("default-src 'self'", $report->originalPolicy);
        $this->assertSame('https://example.com/', $report->referrer);
        $this->assertSame(ReportDisposition::ENFORCE, $report->disposition);
        $this->assertSame(200, $report->statusCode);
        $this->assertSame('alert(1)', $report->scriptSample);
        $this->assertSame('https://example.com/app.js', $report->source->file);
        $this->assertSame(12, $report->source->line);
        $this->assertSame(5, $report->source->column);
        $this->assertSame('', $report->userAgent);
    }

    #[Test]
    public function testDerivesTheEffectiveDirectiveFromTheViolatedOne(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'style-src cdn.example.com',
        ]);

        $this->assertSame('style-src cdn.example.com', $report->violatedDirective);
        $this->assertSame('style-src', $report->effectiveDirective);
    }

    #[Test]
    public function testKeepsABareViolatedDirectiveAsTheEffectiveOne(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'style-src',
        ]);

        $this->assertSame('style-src', $report->effectiveDirective);
    }

    #[Test]
    public function testDerivesTheViolatedDirectiveFromTheEffectiveOne(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'        => 'https://example.com/',
            'effective-directive' => 'img-src',
        ]);

        $this->assertSame('img-src', $report->violatedDirective);
        $this->assertSame('img-src', $report->effectiveDirective);
    }

    #[Test]
    public function testRejectsAReportWithoutAnyDirective(): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('missing the required field: violated-directive');

        $this->parseLegacyBody(['document-uri' => 'https://example.com/']);
    }

    #[Test]
    public function testRejectsAReportWithoutADocumentUri(): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('missing the required field: document-uri');

        $this->parseLegacyBody(['violated-directive' => 'script-src']);
    }

    // ---------------------------------------------------------------
    // Sanitization
    // ---------------------------------------------------------------

    #[Test]
    public function testStripsControlCharactersInsteadOfRejectingTheReport(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'script-src',
            'script-sample'      => "alert(1)\n2026-01-01 CRITICAL forged log line",
            'blocked-uri'        => "https://evil.example.com/\r\n",
        ]);

        $this->assertSame('alert(1)2026-01-01 CRITICAL forged log line', $report->scriptSample);
        $this->assertSame('https://evil.example.com/', $report->blockedUri);
    }

    #[Test]
    public function testStripsUnicodeLineSeparators(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'script-src',
            'script-sample'      => "alert(1)\u{2028}forged\u{2029}lines\u{0085}too",
        ]);

        $this->assertSame('alert(1)forgedlinestoo', $report->scriptSample);
    }

    #[Test]
    public function testStripsNulBytes(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => "https://example.com/\u{0000}",
            'violated-directive' => 'script-src',
        ]);

        $this->assertSame('https://example.com/', $report->documentUri);
    }

    #[Test]
    public function testTruncatesAnOversizedFieldInsteadOfRejectingTheReport(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'script-src',
            'blocked-uri'        => str_repeat('a', CspViolationReport::MAX_URI_LENGTH + 100),
        ]);

        $this->assertSame(CspViolationReport::MAX_URI_LENGTH, strlen($report->blockedUri));
    }

    #[Test]
    public function testTruncatesOnCharactersRatherThanBytes(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'script-src',
            'script-sample'      => str_repeat('ä', CspViolationReport::MAX_SAMPLE_LENGTH + 10),
        ]);

        $this->assertSame(
            CspViolationReport::MAX_SAMPLE_LENGTH,
            mb_strlen($report->scriptSample, 'UTF-8'),
            'Truncation must not split a multi-byte character'
        );
    }

    // ---------------------------------------------------------------
    // Optional field typing
    // ---------------------------------------------------------------

    /**
     * @return iterable<string, array{mixed, ReportDisposition|null}>
     */
    public static function dispositionProvider(): iterable
    {
        yield 'enforce' => ['enforce', ReportDisposition::ENFORCE];
        yield 'report' => ['report', ReportDisposition::REPORT];
        yield 'unknown' => ['blocked', null];
        yield 'wrong case' => ['Enforce', null];
        yield 'not a string' => [1, null];
        yield 'null' => [null, null];
    }

    #[DataProvider('dispositionProvider')]
    #[Test]
    public function testReadsTheDisposition(mixed $value, ?ReportDisposition $expected): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'script-src',
            'disposition'        => $value,
        ]);

        $this->assertSame($expected, $report->disposition);
    }

    /**
     * @return iterable<string, array{mixed, int|null}>
     */
    public static function statusCodeProvider(): iterable
    {
        yield 'integer' => [200, 200];
        yield 'zero' => [0, 0];
        yield 'numeric string' => ['404', 404];
        yield 'negative integer' => [-1, null];
        yield 'float' => [200.5, null];
        yield 'non numeric string' => ['two hundred', null];
        yield 'signed string' => ['-404', null];
        yield 'boolean' => [true, null];
        yield 'null' => [null, null];
    }

    #[DataProvider('statusCodeProvider')]
    #[Test]
    public function testReadsTheStatusCode(mixed $value, ?int $expected): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'script-src',
            'status-code'        => $value,
        ]);

        $this->assertSame($expected, $report->statusCode);
    }

    #[Test]
    public function testTreatsAnEmptyStringFieldAsNotReported(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'script-src',
            'blocked-uri'        => '',
        ]);

        $this->assertSame('', $report->blockedUri);
    }

    #[Test]
    public function testTreatsANonStringFieldAsNotReported(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'script-src',
            'blocked-uri'        => ['nested'],
        ]);

        $this->assertSame('', $report->blockedUri);
    }

    #[Test]
    public function testFallsBackToTheSecondKeySpelling(): void
    {
        $report = $this->parseLegacyBody([
            'documentURL'        => 'https://example.com/camel',
            'violated-directive' => 'script-src',
            'blocked-uri'        => '',
            'blockedURL'         => 'https://evil.example.com/x.js',
        ]);

        $this->assertSame('https://example.com/camel', $report->documentUri);
        $this->assertSame('https://evil.example.com/x.js', $report->blockedUri);
    }

    #[Test]
    public function testPrefersTheFirstKeySpelling(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/kebab',
            'documentURL'        => 'https://example.com/camel',
            'violated-directive' => 'script-src',
        ]);

        $this->assertSame('https://example.com/kebab', $report->documentUri);
    }

    #[Test]
    public function testFallsBackToTheSecondNumericKeySpelling(): void
    {
        $report = $this->parseLegacyBody([
            'document-uri'       => 'https://example.com/',
            'violated-directive' => 'script-src',
            'line-number'        => 'not a number',
            'lineNumber'         => 42,
        ]);

        $this->assertSame(42, $report->source->line);
    }

    // ---------------------------------------------------------------
    // Reporting API batches
    // ---------------------------------------------------------------

    #[Test]
    public function testParsesAReportingApiBatch(): void
    {
        $payload = json_encode([
            [
                'age'        => 53_531,
                'type'       => 'csp-violation',
                'url'        => 'https://example.com/signup',
                'user_agent' => 'Mozilla/5.0',
                'body'       => [
                    'documentURL'        => 'https://example.com/signup',
                    'blockedURL'         => 'https://evil.example.com/payload.js',
                    'effectiveDirective' => 'script-src-elem',
                    'originalPolicy'     => "default-src 'self'",
                    'referrer'           => 'https://example.com/',
                    'disposition'        => 'report',
                    'statusCode'         => 200,
                    'sample'             => 'alert(1)',
                    'sourceFile'         => 'https://example.com/app.js',
                    'lineNumber'         => 12,
                    'columnNumber'       => 5,
                ],
            ],
        ], JSON_THROW_ON_ERROR);

        $reports = $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_REPORTING_API);

        $this->assertCount(1, $reports);

        $report = $reports[0];
        $this->assertSame('https://example.com/signup', $report->documentUri);
        $this->assertSame('script-src-elem', $report->effectiveDirective);
        $this->assertSame('script-src-elem', $report->violatedDirective);
        $this->assertSame('https://evil.example.com/payload.js', $report->blockedUri);
        $this->assertSame(ReportDisposition::REPORT, $report->disposition);
        $this->assertSame(200, $report->statusCode);
        $this->assertSame('alert(1)', $report->scriptSample);
        $this->assertSame('https://example.com/app.js', $report->source->file);
        $this->assertSame('Mozilla/5.0', $report->userAgent);
    }

    #[Test]
    public function testSkipsReportTypesOtherThanCspViolations(): void
    {
        $payload = json_encode([
            ['type' => 'deprecation', 'body' => ['id' => 'PrefixedStorageInfo']],
            ['type' => 'csp-violation', 'body' => [
                'documentURL'        => 'https://example.com/',
                'effectiveDirective' => 'img-src',
            ]],
            ['type' => 'intervention', 'body' => ['id' => 'HeavyAdIntervention']],
        ], JSON_THROW_ON_ERROR);

        $reports = $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_REPORTING_API);

        $this->assertCount(1, $reports);
        $this->assertSame('img-src', $reports[0]->effectiveDirective);
    }

    #[Test]
    public function testAcceptsABatchWithoutAnyCspViolation(): void
    {
        $payload = json_encode([
            ['type' => 'deprecation', 'body' => ['id' => 'PrefixedStorageInfo']],
        ], JSON_THROW_ON_ERROR);

        $this->assertSame([], $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_REPORTING_API));
    }

    #[Test]
    public function testAcceptsAnEmptyBatch(): void
    {
        $this->assertSame([], $this->parser->parse('[]', CspReportParser::CONTENT_TYPE_REPORTING_API));
    }

    #[Test]
    public function testIgnoresANonStringUserAgent(): void
    {
        $payload = json_encode([
            ['type' => 'csp-violation', 'user_agent' => 42, 'body' => [
                'documentURL'        => 'https://example.com/',
                'effectiveDirective' => 'img-src',
            ]],
        ], JSON_THROW_ON_ERROR);

        $reports = $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_REPORTING_API);

        $this->assertSame('', $reports[0]->userAgent);
    }

    #[Test]
    public function testAcceptsABatchAtTheSizeLimit(): void
    {
        $payload = self::batchOf(CspReportParser::MAX_REPORTS_PER_BATCH);

        $this->assertCount(
            CspReportParser::MAX_REPORTS_PER_BATCH,
            $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_REPORTING_API)
        );
    }

    #[Test]
    public function testRejectsABatchBeyondTheSizeLimit(): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('more than 32 reports');

        $this->parser->parse(
            self::batchOf(CspReportParser::MAX_REPORTS_PER_BATCH + 1),
            CspReportParser::CONTENT_TYPE_REPORTING_API
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedBatchProvider(): iterable
    {
        yield 'object instead of list' => ['{"type": "csp-violation"}'];
        yield 'sparse list' => ['{"1": {"type": "csp-violation"}}'];
        // Structurally a valid report, but keyed - a batch must be a JSON array
        yield 'string keyed report' => ['{"a": {"type": "csp-violation", "body": {"documentURL": "https://example.com/", "effectiveDirective": "img-src"}}}'];
        yield 'entry not an object' => ['["csp-violation"]'];
        yield 'body missing' => ['[{"type": "csp-violation"}]'];
        yield 'body not an object' => ['[{"type": "csp-violation", "body": "nope"}]'];
    }

    #[DataProvider('malformedBatchProvider')]
    #[Test]
    public function testRejectsAMalformedBatch(string $payload): void
    {
        $this->expectException(CspReportException::class);
        $this->expectExceptionMessage('unexpected structure');

        $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_REPORTING_API);
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * @param array<string, mixed> $body
     *
     * @throws JsonException If the fixture cannot be encoded
     */
    private function parseLegacyBody(array $body): CspViolationReport
    {
        $payload = json_encode(['csp-report' => $body], JSON_THROW_ON_ERROR);

        return $this->parser->parse($payload, CspReportParser::CONTENT_TYPE_LEGACY)[0];
    }

    private static function legacyPayload(): string
    {
        return json_encode(['csp-report' => [
            'document-uri'        => 'https://example.com/signup',
            'referrer'            => 'https://example.com/',
            'violated-directive'  => 'script-src https://cdn.example.com',
            'effective-directive' => 'script-src-elem',
            'original-policy'     => "default-src 'self'",
            'blocked-uri'         => 'https://evil.example.com/payload.js',
            'disposition'         => 'enforce',
            'status-code'         => 200,
            'script-sample'       => 'alert(1)',
            'source-file'         => 'https://example.com/app.js',
            'line-number'         => 12,
            'column-number'       => 5,
        ]], JSON_THROW_ON_ERROR);
    }

    /**
     * Build a syntactically valid legacy payload of exactly the given size
     */
    private static function legacyPayloadOfSize(int $bytes): string
    {
        $template = '{"csp-report":{"document-uri":"https://example.com/","violated-directive":"script-src","padding":"%s"}}';
        $padding  = str_repeat('a', $bytes - strlen(sprintf($template, '')));

        return sprintf($template, $padding);
    }

    private static function legacyWithExtra(string $extraJson): string
    {
        return sprintf(
            '{"csp-report":{"document-uri":"https://example.com/","violated-directive":"script-src","extra":%s}}',
            $extraJson
        );
    }

    /**
     * Build a JSON array nested the given number of levels deep
     */
    private static function nested(int $levels): string
    {
        return str_repeat('[', $levels) . '1' . str_repeat(']', $levels);
    }

    private static function batchOf(int $count): string
    {
        $entries = array_map(
            static fn (int $index): array => [
                'type' => 'csp-violation',
                'body' => [
                    'documentURL'        => sprintf('https://example.com/page-%d', $index),
                    'effectiveDirective' => 'img-src',
                ],
            ],
            range(1, $count)
        );

        return json_encode($entries, JSON_THROW_ON_ERROR);
    }
}
