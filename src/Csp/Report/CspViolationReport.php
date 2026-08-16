<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Report;

use Zappzarapp\Security\Csp\Exception\CspReportException;

/**
 * A single CSP violation report, normalized across both wire formats
 *
 * Browsers deliver violations either as a legacy `report-uri` payload
 * (`application/csp-report`, kebab-case keys) or through the Reporting API
 * (`application/reports+json`, camelCase keys). Both are parsed into this
 * shape by {@see CspReportParser}, so consumers never deal with the
 * spelling differences.
 *
 * ## Trust model
 *
 * A violation report is *not* trustworthy input. Anyone can POST to a
 * report endpoint, and even a genuine browser report contains
 * attacker-chosen substrings - a blocked URI and a script sample are taken
 * verbatim from the injected content. The constructor therefore enforces
 * the invariants that make a report safe to log: no control characters
 * (log injection) and a hard length cap per field (log flooding).
 *
 * Values coming off the wire are stripped and truncated by the parser
 * before they reach this constructor. Constructing one directly is
 * supported, but the caller then owns those guarantees - the constructor
 * rejects rather than sanitizes.
 *
 * @see https://www.w3.org/TR/CSP3/#deprecated-serialize-violation Legacy format
 * @see https://www.w3.org/TR/CSP3/#create-violation-events Reporting API format
 */
final readonly class CspViolationReport
{
    use ValidatesReportFields;

    /**
     * Maximum accepted length of a URI-valued field
     */
    public const int MAX_URI_LENGTH = 2048;

    /**
     * Maximum accepted length of a directive-valued field
     */
    public const int MAX_DIRECTIVE_LENGTH = 256;

    /**
     * Maximum accepted length of the original policy
     */
    public const int MAX_POLICY_LENGTH = 4096;

    /**
     * Maximum accepted length of the script sample
     *
     * Browsers cap the sample at 40 characters; the extra headroom absorbs
     * non-conforming clients without turning the log into a payload store.
     */
    public const int MAX_SAMPLE_LENGTH = 200;

    /**
     * Maximum accepted length of the reported user agent
     */
    public const int MAX_USER_AGENT_LENGTH = 512;

    /**
     * @param string $documentUri URI of the document the violation occurred in (required)
     * @param string $violatedDirective The directive that was violated, possibly including its value list (required)
     * @param string $effectiveDirective The directive name that was violated (required)
     * @param string $blockedUri URI of the resource that was blocked, empty when not reported
     * @param string $originalPolicy The full policy the violation was measured against
     * @param string $referrer Referrer of the violating document
     * @param ReportDisposition|null $disposition Whether the policy was enforced, null when not reported
     * @param int|null $statusCode HTTP status code of the violating document
     * @param string $scriptSample Excerpt of the violating inline script or style
     * @param ViolationSource $source Source location of the violation
     * @param string $userAgent User agent, only reported through the Reporting API
     *
     * @throws CspReportException If a required field is empty or a value is unsafe, too long or negative
     */
    public function __construct(
        public string $documentUri,
        public string $violatedDirective,
        public string $effectiveDirective,
        public string $blockedUri = '',
        public string $originalPolicy = '',
        public string $referrer = '',
        public ?ReportDisposition $disposition = null,
        public ?int $statusCode = null,
        public string $scriptSample = '',
        public ViolationSource $source = new ViolationSource(),
        public string $userAgent = '',
    ) {
        $this->assertRequired('document-uri', $this->documentUri);
        $this->assertRequired('violated-directive', $this->violatedDirective);
        $this->assertRequired('effective-directive', $this->effectiveDirective);

        $this->assertClean('document-uri', $this->documentUri, self::MAX_URI_LENGTH);
        $this->assertClean('violated-directive', $this->violatedDirective, self::MAX_DIRECTIVE_LENGTH);
        $this->assertClean('effective-directive', $this->effectiveDirective, self::MAX_DIRECTIVE_LENGTH);
        $this->assertClean('blocked-uri', $this->blockedUri, self::MAX_URI_LENGTH);
        $this->assertClean('original-policy', $this->originalPolicy, self::MAX_POLICY_LENGTH);
        $this->assertClean('referrer', $this->referrer, self::MAX_URI_LENGTH);
        $this->assertClean('script-sample', $this->scriptSample, self::MAX_SAMPLE_LENGTH);
        $this->assertClean('user-agent', $this->userAgent, self::MAX_USER_AGENT_LENGTH);

        $this->assertNonNegative('status-code', $this->statusCode);
    }

    /**
     * Whether the violating resource was actually blocked
     *
     * Reports without a disposition are treated as non-blocking, because
     * only an explicit `enforce` disposition proves the policy was live.
     */
    public function wasBlocked(): bool
    {
        return $this->disposition?->isBlocking() ?? false;
    }

    /**
     * Convert to log context fields
     *
     * Keys use the snake_case convention of the logging module. Fields the
     * browser did not report are `null` rather than an empty string, so a
     * "not reported" is distinguishable from a reported empty value.
     *
     * @return array<string, string|int|null>
     */
    public function toLogContext(): array
    {
        return [
            'document_uri'        => $this->documentUri,
            'violated_directive'  => $this->violatedDirective,
            'effective_directive' => $this->effectiveDirective,
            'blocked_uri'         => $this->blockedUri !== '' ? $this->blockedUri : null,
            'original_policy'     => $this->originalPolicy !== '' ? $this->originalPolicy : null,
            'referrer'            => $this->referrer !== '' ? $this->referrer : null,
            'disposition'         => $this->disposition?->value,
            'status_code'         => $this->statusCode,
            'script_sample'       => $this->scriptSample !== '' ? $this->scriptSample : null,
            ...$this->source->toLogContext(),
            'user_agent'          => $this->userAgent !== '' ? $this->userAgent : null,
        ];
    }

    /**
     * Reject an empty required field
     *
     * @throws CspReportException If the value is empty
     */
    private function assertRequired(string $field, string $value): void
    {
        if ($value === '') {
            throw CspReportException::missingField($field);
        }
    }
}
