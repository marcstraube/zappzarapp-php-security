<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a CSP violation report cannot be accepted
 *
 * Every rejection reason is a fixed, developer-facing string. Report
 * payloads are attacker-controlled, so no part of the payload is ever
 * interpolated into a message: the message ends up in the security log and
 * must not become a log injection or reflection vector.
 */
final class CspReportException extends InvalidArgumentException
{
    /**
     * Create for a request body larger than the configured limit
     */
    public static function payloadTooLarge(int $maxBytes): self
    {
        return new self(sprintf(
            'CSP report payload exceeds the maximum of %d bytes',
            $maxBytes
        ));
    }

    /**
     * Create for a Content-Type the endpoint does not accept
     *
     * The received Content-Type is deliberately not echoed back.
     */
    public static function unsupportedContentType(): self
    {
        return new self('CSP report has an unsupported Content-Type');
    }

    /**
     * Create for a request body that could not be read to the end
     *
     * The underlying stream error is deliberately not carried over: it
     * describes server internals and has no place in the security log.
     */
    public static function unreadableBody(): self
    {
        return new self('CSP report body could not be read');
    }

    /**
     * Create for a body that is not valid JSON
     */
    public static function malformedJson(): self
    {
        return new self('CSP report body is not valid JSON');
    }

    /**
     * Create for a JSON document with the wrong top-level shape
     */
    public static function malformedEnvelope(): self
    {
        return new self('CSP report envelope has an unexpected structure');
    }

    /**
     * Create for a batch containing more reports than allowed
     */
    public static function tooManyReports(int $maxReports): self
    {
        return new self(sprintf(
            'CSP report batch contains more than %d reports',
            $maxReports
        ));
    }

    /**
     * Create for a required report field that is missing or empty
     */
    public static function missingField(string $field): self
    {
        return new self(sprintf(
            'CSP report is missing the required field: %s',
            $field
        ));
    }

    /**
     * Create for a field value that is not valid UTF-8
     *
     * Matters beyond tidiness: the sanitization patterns are Unicode-aware,
     * and a Unicode pattern does not match at all against malformed input.
     * Rejecting up front keeps a broken encoding from smuggling a control
     * character past a check that silently failed.
     */
    public static function malformedEncoding(string $field): self
    {
        return new self(sprintf(
            'CSP report field is not valid UTF-8: %s',
            $field
        ));
    }

    /**
     * Create for a field value containing control characters
     */
    public static function containsControlCharacters(string $field): self
    {
        return new self(sprintf(
            'CSP report field must not contain control characters: %s',
            $field
        ));
    }

    /**
     * Create for a field value exceeding its length limit
     */
    public static function fieldTooLong(string $field, int $maxLength): self
    {
        return new self(sprintf(
            'CSP report field %s exceeds the maximum of %d characters',
            $field,
            $maxLength
        ));
    }

    /**
     * Create for a numeric field with a negative value
     */
    public static function negativeValue(string $field): self
    {
        return new self(sprintf(
            'CSP report field must not be negative: %s',
            $field
        ));
    }

    /**
     * Create for a payload size limit that is not usable
     */
    public static function invalidPayloadLimit(int $maxBytes): self
    {
        return new self(sprintf(
            'Maximum payload size must be at least 1 byte, got %d',
            $maxBytes
        ));
    }
}
