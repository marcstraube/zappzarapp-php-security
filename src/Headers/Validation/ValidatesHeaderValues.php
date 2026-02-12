<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\Validation;

use Zappzarapp\Security\Headers\Exception\InvalidHeaderValueException;

/**
 * Validates security header values for injection attacks
 *
 * Prevents HTTP header injection by rejecting values containing:
 * - Control characters (0x00-0x1F) including CR/LF that could inject headers
 *
 * Note: Not all header components use this trait. Enum-based components
 * (e.g., Coop, Coep, Corp, ReferrerPolicy, XFrameOptions) are type-safe
 * by design - they use predefined constants and don't accept user input,
 * so header injection is structurally impossible. This trait is used by
 * components that accept arbitrary string values (e.g., HstsConfig,
 * PermissionsPolicyDirective, CSP directives).
 */
trait ValidatesHeaderValues
{
    /**
     * Validate header value for injection attacks
     *
     * @throws InvalidHeaderValueException If value contains control characters
     */
    private function validateHeaderValue(string $header, string $value): void
    {
        if (preg_match('/[\x00-\x1F]/', $value) === 1) {
            throw InvalidHeaderValueException::containsControlCharacter($header, $value);
        }
    }
}
