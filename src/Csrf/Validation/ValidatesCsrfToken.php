<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Validation;

use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Token\CsrfToken;

/**
 * Trait for validating CSRF tokens
 *
 * Provides timing-safe token comparison.
 */
trait ValidatesCsrfToken
{
    /**
     * Validate a submitted token against an expected value
     *
     * @param string $submitted The token submitted with the request
     * @param string $expected The expected token value
     *
     * @throws CsrfTokenMismatchException If tokens don't match
     * @throws InvalidCsrfTokenException If token format is invalid
     */
    private function validateCsrfToken(string $submitted, string $expected): void
    {
        if ($submitted === '') {
            throw CsrfTokenMismatchException::missingToken();
        }

        if ($expected === '') {
            throw CsrfTokenMismatchException::noStoredToken();
        }

        // Validate format
        $submittedToken = new CsrfToken($submitted);

        // Timing-safe comparison
        if (!hash_equals($expected, $submittedToken->value())) {
            throw CsrfTokenMismatchException::tokenMismatch();
        }
    }
}
