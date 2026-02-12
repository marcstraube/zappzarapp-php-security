<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a CSP directive value contains invalid characters
 *
 * Prevents CSP header injection attacks via semicolon or control characters.
 */
final class InvalidDirectiveValueException extends InvalidArgumentException
{
    /**
     * Create exception for semicolon in directive value
     */
    public static function containsSemicolon(string $directive, string $value): self
    {
        return new self(sprintf(
            'Directive "%s" value contains semicolon which could lead to CSP injection: %s',
            $directive,
            $value
        ));
    }

    /**
     * Create exception for control character in directive value
     */
    public static function containsControlCharacter(string $directive, string $value): self
    {
        // Escape all control characters for safe display
        $escaped = preg_replace_callback(
            '/[\x00-\x1F]/',
            static fn(array $m): string => '\\x' . strtoupper(bin2hex($m[0])),
            $value
        ) ?? $value;

        return new self(sprintf(
            'Directive "%s" value contains control character which could lead to header injection: %s',
            $directive,
            $escaped
        ));
    }

    /**
     * Create exception for unicode whitespace in directive value
     */
    public static function containsUnicodeWhitespace(string $directive, string $value): self
    {
        return new self(sprintf(
            'Directive "%s" value contains unicode whitespace which could cause parser inconsistencies: %s',
            $directive,
            $value
        ));
    }

    /**
     * Create exception for invalid WebSocket host format
     */
    public static function invalidWebSocketHost(string $host): self
    {
        return new self(sprintf(
            'WebSocket host format is invalid: "%s" (expected: host:port)',
            $host
        ));
    }

    /**
     * Create exception for invalid WebSocket port
     */
    public static function invalidWebSocketPort(string $host, int $port): self
    {
        return new self(sprintf(
            'WebSocket port is out of range: "%s" (port %d must be between 1 and 65535)',
            $host,
            $port
        ));
    }

    /**
     * Create exception for invalid nonce value
     */
    public static function invalidNonce(string $nonce, string $reason): self
    {
        // Escape all control characters for safe display
        $escaped = preg_replace_callback(
            '/[\x00-\x1F]/',
            static fn(array $m): string => '\\x' . strtoupper(bin2hex($m[0])),
            $nonce
        ) ?? $nonce;

        return new self(sprintf(
            'Nonce value is invalid (%s): %s',
            $reason,
            $escaped
        ));
    }

    /**
     * Create exception for insecure report-uri scheme
     */
    public static function insecureReportUri(string $uri): self
    {
        return new self(sprintf(
            'Report-URI must use HTTPS to protect sensitive violation data: %s',
            $uri
        ));
    }
}
