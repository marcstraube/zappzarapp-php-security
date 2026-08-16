<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Report;

use Zappzarapp\Security\Csp\Exception\CspReportException;

/**
 * Shared field handling for CSP violation reports
 *
 * Report fields originate from a browser but are attacker-influenced: a
 * violation can be provoked deliberately, and both the blocked URI and the
 * script sample carry content chosen by the attacker. Two things follow,
 * and this trait holds both so they can never drift apart:
 *
 * - {@see self::sanitizeField()} is what the parser applies to values off
 *   the wire, stripping the offending characters and truncating.
 * - {@see self::assertClean()} is what the value objects enforce, rejecting
 *   anything the parser would have removed.
 */
trait ValidatesReportFields
{
    /**
     * Matches every character that can begin a new line in a log file:
     * the ASCII control range including NUL and DEL, plus the Unicode
     * line separators NEL, LINE SEPARATOR and PARAGRAPH SEPARATOR
     */
    private const string CONTROL_CHARACTERS = '/[\x00-\x1F\x7F\x{0085}\x{2028}\x{2029}]/u';

    /**
     * Strip control characters and truncate to the field limit
     *
     * A Unicode pattern does not match at all against malformed UTF-8 -
     * preg_replace() returns null rather than a partially cleaned string.
     * Collapsing that to an empty value is deliberate: an unusable field is
     * dropped, and the value objects reject what is then missing.
     */
    private function sanitizeField(string $value, int $maxLength): string
    {
        $stripped = preg_replace(self::CONTROL_CHARACTERS, '', $value) ?? '';

        return mb_substr($stripped, 0, $maxLength, 'UTF-8');
    }

    /**
     * Reject an unusable value in a report field
     *
     * The encoding check comes first and is not a formality: a Unicode
     * pattern fails to match against malformed UTF-8, so without it a
     * broken encoding would carry a control character past a check that
     * silently returned "no match".
     *
     * @param string $field Canonical field name, used for the error message only
     *
     * @throws CspReportException If the value is malformed, unsafe or too long
     */
    private function assertClean(string $field, string $value, int $maxLength): void
    {
        if (!mb_check_encoding($value, 'UTF-8')) {
            throw CspReportException::malformedEncoding($field);
        }

        if (preg_match(self::CONTROL_CHARACTERS, $value) === 1) {
            throw CspReportException::containsControlCharacters($field);
        }

        if (mb_strlen($value, 'UTF-8') > $maxLength) {
            throw CspReportException::fieldTooLong($field, $maxLength);
        }
    }

    /**
     * Reject negative values in a numeric report field
     *
     * @param string $field Canonical field name, used for the error message only
     *
     * @throws CspReportException If the value is negative
     */
    private function assertNonNegative(string $field, ?int $value): void
    {
        if ($value !== null && $value < 0) {
            throw CspReportException::negativeValue($field);
        }
    }
}
