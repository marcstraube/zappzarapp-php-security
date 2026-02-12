<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.3 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Token;

use LogicException;
use Override;
use PHPUnit\Framework\TestCase;

/**
 * Null CSRF token provider for testing
 *
 * Always returns a fixed, predictable token. This class is intended
 * ONLY for testing environments and should NEVER be used in production.
 *
 * ## Security Warning
 *
 * Using this class in production completely disables CSRF protection,
 * as the token is predictable and can be forged by attackers.
 *
 * ## Environment Check
 *
 * By default, this class will throw an exception if instantiated
 * outside of a testing environment (detected via common test frameworks).
 * You can bypass this check by passing `allowProduction: true`, but
 * this is strongly discouraged.
 *
 * @internal This class is intended for testing only
 */
final readonly class NullCsrfToken implements CsrfTokenProvider
{
    private CsrfToken $token;

    /**
     * @param string|null $token Custom token value (optional)
     * @param bool $allowProduction Bypass production check (DANGEROUS)
     *
     * @throws LogicException If used outside testing environment without explicit override
     *
     * @SuppressWarnings(BooleanArgumentFlag) Security bypass flag, intentionally explicit
     */
    public function __construct(
        ?string $token = null,
        bool $allowProduction = false,
    ) {
        if (!$allowProduction && !$this->isTestEnvironment()) {
            throw new LogicException(
                'NullCsrfToken is intended for testing only and should not be used in production. ' .
                'It provides predictable tokens that can be forged by attackers. ' .
                'If you really need to disable CSRF protection, pass allowProduction: true.'
            );
        }

        // Use a fixed token that meets minimum requirements
        $this->token = new CsrfToken($token ?? base64_encode(str_repeat('0', CsrfToken::MIN_BYTES)));
    }

    /**
     * Detect if running in a testing environment
     *
     * Checks for common test framework indicators:
     * - PHPUnit (PHPUNIT_COMPOSER_INSTALL, __PHPUNIT_CONFIGURATION_FILE__)
     * - Pest/PHPUnit bootstrap
     * - Common test environment variables
     */
    private function isTestEnvironment(): bool
    {
        // PHPUnit sets these constants/env vars
        if (defined('PHPUNIT_COMPOSER_INSTALL') || defined('__PHPUNIT_CONFIGURATION_FILE__')) {
            return true;
        }

        // Common test environment indicators
        if (getenv('PHPUNIT_TEST') !== false || getenv('APP_ENV') === 'testing') {
            return true;
        }

        // Check if PHPUnit classes are loaded (in-process testing)
        return class_exists(TestCase::class, false);
    }

    #[Override]
    public function get(): CsrfToken
    {
        return $this->token;
    }

    #[Override]
    public function reset(): void
    {
        // Null implementation - token never changes
    }
}
