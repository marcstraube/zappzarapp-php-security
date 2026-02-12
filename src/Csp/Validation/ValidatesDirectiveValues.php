<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp\Validation;

use Zappzarapp\Security\Csp\Exception\InvalidDirectiveValueException;

/**
 * Validates CSP directive values for injection attacks
 *
 * Prevents CSP header injection by rejecting values containing:
 * - Semicolons (;) - directive separators that could inject new directives
 * - Control characters (0x00-0x1F) including CR/LF that could inject headers
 * - Unicode whitespace - potential parser confusion (Defense-in-Depth)
 */
trait ValidatesDirectiveValues
{
    /**
     * Unicode whitespace characters beyond standard ASCII
     *
     * These could potentially cause parser inconsistencies across implementations:
     * - U+00A0: Non-breaking space
     * - U+2000-U+200A: Various typographic spaces
     * - U+202F: Narrow no-break space
     * - U+205F: Medium mathematical space
     * - U+3000: Ideographic space
     */
    private const string UNICODE_WHITESPACE_PATTERN = '/[\x{00A0}\x{2000}-\x{200A}\x{202F}\x{205F}\x{3000}]/u';

    /**
     * Validate directive value for injection attacks
     *
     * @throws InvalidDirectiveValueException If value contains semicolon, control character, or unicode whitespace
     */
    private function validateDirectiveValue(string $directive, string $value): void
    {
        if (str_contains($value, ';')) {
            throw InvalidDirectiveValueException::containsSemicolon($directive, $value);
        }

        if (preg_match('/[\x00-\x1F]/', $value) === 1) {
            throw InvalidDirectiveValueException::containsControlCharacter($directive, $value);
        }

        if (preg_match(self::UNICODE_WHITESPACE_PATTERN, $value) === 1) {
            throw InvalidDirectiveValueException::containsUnicodeWhitespace($directive, $value);
        }
    }
}
