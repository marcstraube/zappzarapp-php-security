<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Report;

use JsonException;
use Zappzarapp\Security\Csp\Exception\CspReportException;

/**
 * Strict parser for CSP violation report payloads
 *
 * Turns the two wire formats browsers use into {@see CspViolationReport}
 * value objects. The parser is the trust boundary of the reporting
 * endpoint: everything it returns is safe to hand to a logger.
 *
 * ## Accepted formats
 *
 * `application/csp-report` - the legacy `report-uri` payload, a single
 * report wrapped in a `csp-report` object with kebab-case keys:
 *
 * ```json
 * {"csp-report": {"document-uri": "https://example.com/", "blocked-uri": "..."}}
 * ```
 *
 * `application/reports+json` - the Reporting API payload used by
 * `report-to`, a batch of envelopes with camelCase body keys:
 *
 * ```json
 * [{"type": "csp-violation", "body": {"documentURL": "...", "blockedURL": "..."}}]
 * ```
 *
 * Both key spellings are accepted in either format, because browsers have
 * shipped the Reporting API with kebab-case bodies at various points.
 *
 * ## Strictness
 *
 * The envelope must be structurally correct and the fields identifying the
 * violation (`document-uri` plus one of `violated-directive` /
 * `effective-directive`) must be present - anything else is rejected with
 * an {@see CspReportException}.
 *
 * Optional fields are lenient by design: a value of the wrong JSON type is
 * treated as "not reported" rather than failing the whole report. A browser
 * quirk in a line number is not a reason to drop a genuine violation, and
 * dropping it would let an attacker suppress reporting by provoking one.
 *
 * Reporting API batches may legitimately mix report types on a shared
 * endpoint, so entries that are not `csp-violation` are skipped rather than
 * rejected.
 *
 * ## Sanitization
 *
 * Every string is stripped of control characters and truncated to its field
 * limit before it reaches the value object. Stripping rather than rejecting
 * matters for `script-sample`, which carries a raw excerpt of the violating
 * markup and routinely contains newlines.
 */
final readonly class CspReportParser
{
    use ValidatesReportFields;

    /**
     * Content-Type of the legacy `report-uri` payload
     */
    public const string CONTENT_TYPE_LEGACY = 'application/csp-report';

    /**
     * Content-Type of the Reporting API payload used by `report-to`
     */
    public const string CONTENT_TYPE_REPORTING_API = 'application/reports+json';

    /**
     * Default maximum accepted payload size in bytes
     */
    public const int DEFAULT_MAX_PAYLOAD_BYTES = 16_384;

    /**
     * Maximum number of reports accepted in a single Reporting API batch
     */
    public const int MAX_REPORTS_PER_BATCH = 32;

    /**
     * Reporting API report type carrying a CSP violation
     */
    private const string REPORT_TYPE = 'csp-violation';

    /**
     * Maximum JSON nesting depth - a report needs three levels
     */
    private const int MAX_JSON_DEPTH = 8;

    /**
     * @param int $maxPayloadBytes Maximum accepted payload size in bytes
     *
     * @throws CspReportException If the limit is below one byte
     */
    public function __construct(
        public int $maxPayloadBytes = self::DEFAULT_MAX_PAYLOAD_BYTES,
    ) {
        if ($this->maxPayloadBytes < 1) {
            throw CspReportException::invalidPayloadLimit($this->maxPayloadBytes);
        }
    }

    /**
     * Parse a report payload into violation reports
     *
     * Returns an empty list when a Reporting API batch contains no CSP
     * violations - a shared endpoint also receives deprecation and
     * intervention reports.
     *
     * @param string $payload Raw request body
     * @param string $contentType Raw Content-Type header value, parameters are ignored
     *
     * @return list<CspViolationReport>
     *
     * @throws CspReportException If the payload is oversized, malformed or of an unsupported type
     */
    public function parse(string $payload, string $contentType): array
    {
        if (strlen($payload) > $this->maxPayloadBytes) {
            throw CspReportException::payloadTooLarge($this->maxPayloadBytes);
        }

        return match ($this->mediaType($contentType)) {
            self::CONTENT_TYPE_LEGACY        => [$this->parseLegacy($this->decode($payload))],
            self::CONTENT_TYPE_REPORTING_API => $this->parseBatch($this->decode($payload)),
            default                          => throw CspReportException::unsupportedContentType(),
        };
    }

    /**
     * Extract the lowercased media type from a Content-Type header value
     */
    private function mediaType(string $contentType): string
    {
        return strtolower(trim($this->upTo($contentType, ';')));
    }

    /**
     * Take everything before the first occurrence of a separator
     */
    private function upTo(string $value, string $separator): string
    {
        $position = strpos($value, $separator);

        return $position === false
            ? $value
            : substr($value, 0, $position);
    }

    /**
     * Decode the payload into an array
     *
     * @return array<array-key, mixed>
     *
     * @throws CspReportException If the payload is not a JSON array or object
     */
    private function decode(string $payload): array
    {
        try {
            $decoded = json_decode($payload, true, self::MAX_JSON_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw CspReportException::malformedJson();
        }

        if (!is_array($decoded)) {
            throw CspReportException::malformedEnvelope();
        }

        return $decoded;
    }

    /**
     * Parse a legacy `application/csp-report` envelope
     *
     * @param array<array-key, mixed> $envelope
     *
     * @throws CspReportException If the envelope or the report is malformed
     */
    private function parseLegacy(array $envelope): CspViolationReport
    {
        $body = $envelope['csp-report'] ?? null;

        if (!is_array($body)) {
            throw CspReportException::malformedEnvelope();
        }

        return $this->buildReport($body, '');
    }

    /**
     * Parse an `application/reports+json` batch
     *
     * @param array<array-key, mixed> $envelope
     *
     * @return list<CspViolationReport>
     *
     * @throws CspReportException If the batch is oversized or an entry is malformed
     */
    private function parseBatch(array $envelope): array
    {
        if (!array_is_list($envelope)) {
            throw CspReportException::malformedEnvelope();
        }

        if (count($envelope) > self::MAX_REPORTS_PER_BATCH) {
            throw CspReportException::tooManyReports(self::MAX_REPORTS_PER_BATCH);
        }

        $reports = [];

        foreach ($envelope as $entry) {
            if (!is_array($entry)) {
                throw CspReportException::malformedEnvelope();
            }

            // A report-to group also receives deprecation and intervention reports
            if (($entry['type'] ?? null) !== self::REPORT_TYPE) {
                continue;
            }

            $body = $entry['body'] ?? null;

            if (!is_array($body)) {
                throw CspReportException::malformedEnvelope();
            }

            $userAgent = $this->stringValue($entry, ['user_agent'], CspViolationReport::MAX_USER_AGENT_LENGTH);

            $reports[] = $this->buildReport($body, $userAgent);
        }

        return $reports;
    }

    /**
     * Build a violation report from a report body
     *
     * @param array<array-key, mixed> $body
     *
     * @throws CspReportException If a required field is missing
     */
    private function buildReport(array $body, string $userAgent): CspViolationReport
    {
        $violated  = $this->stringValue($body, ['violated-directive', 'violatedDirective'], CspViolationReport::MAX_DIRECTIVE_LENGTH);
        $effective = $this->stringValue($body, ['effective-directive', 'effectiveDirective'], CspViolationReport::MAX_DIRECTIVE_LENGTH);

        return new CspViolationReport(
            documentUri: $this->stringValue($body, ['document-uri', 'documentURL'], CspViolationReport::MAX_URI_LENGTH),
            // Browsers report only one of the two often enough that the other is derived.
            // violated-directive may carry the full directive including its value list
            // ("style-src cdn.example.com"), effective-directive never does.
            violatedDirective: $violated !== '' ? $violated : $effective,
            effectiveDirective: $effective !== '' ? $effective : $this->upTo($violated, ' '),
            blockedUri: $this->stringValue($body, ['blocked-uri', 'blockedURL'], CspViolationReport::MAX_URI_LENGTH),
            originalPolicy: $this->stringValue($body, ['original-policy', 'originalPolicy'], CspViolationReport::MAX_POLICY_LENGTH),
            referrer: $this->stringValue($body, ['referrer'], CspViolationReport::MAX_URI_LENGTH),
            disposition: $this->disposition($body),
            statusCode: $this->intValue($body, ['status-code', 'statusCode']),
            scriptSample: $this->stringValue($body, ['script-sample', 'sample'], CspViolationReport::MAX_SAMPLE_LENGTH),
            source: new ViolationSource(
                file: $this->stringValue($body, ['source-file', 'sourceFile'], ViolationSource::MAX_FILE_LENGTH),
                line: $this->intValue($body, ['line-number', 'lineNumber']),
                column: $this->intValue($body, ['column-number', 'columnNumber']),
            ),
            userAgent: $userAgent,
        );
    }

    /**
     * Read the disposition of the reported violation
     *
     * Matched against the enum verbatim: an unknown or non-string value is
     * "not reported" rather than a guess, so no length cap is needed.
     *
     * @param array<array-key, mixed> $body
     */
    private function disposition(array $body): ?ReportDisposition
    {
        $value = $body['disposition'] ?? null;

        return is_string($value)
            ? ReportDisposition::tryFrom($value)
            : null;
    }

    /**
     * Read the first present string field under any of the given key spellings
     *
     * Values of another JSON type count as absent.
     *
     * @param array<array-key, mixed> $body
     * @param non-empty-list<string> $keys
     */
    private function stringValue(array $body, array $keys, int $maxLength): string
    {
        foreach ($keys as $key) {
            $value = $body[$key] ?? null;

            if (is_string($value) && $value !== '') {
                return $this->sanitizeField($value, $maxLength);
            }
        }

        return '';
    }

    /**
     * Read the first present integer field under any of the given key spellings
     *
     * Accepts JSON numbers and numeric strings; anything else counts as
     * absent. Negative values are dropped here rather than rejected,
     * keeping a quirky browser from suppressing a genuine report.
     *
     * @param array<array-key, mixed> $body
     * @param non-empty-list<string> $keys
     */
    private function intValue(array $body, array $keys): ?int
    {
        foreach ($keys as $key) {
            $value = $body[$key] ?? null;

            if (is_int($value) && $value >= 0) {
                return $value;
            }

            if (is_string($value) && ctype_digit($value)) {
                return (int) $value;
            }
        }

        return null;
    }
}
