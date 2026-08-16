<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Report;

/**
 * Disposition of a reported CSP violation
 *
 * Tells whether the policy that produced the report was actually enforced
 * or was only running in report-only mode. Reports without a disposition
 * are represented as `null` rather than being defaulted, because guessing
 * would misrepresent whether the violation was blocked.
 *
 * @see https://www.w3.org/TR/CSP3/#violation-disposition
 */
enum ReportDisposition: string
{
    /**
     * The policy was enforced - the resource was actually blocked
     */
    case ENFORCE = 'enforce';

    /**
     * The policy ran in report-only mode - the resource was allowed
     */
    case REPORT = 'report';

    /**
     * Whether the violating resource was actually blocked
     */
    public function isBlocking(): bool
    {
        return $this === self::ENFORCE;
    }
}
