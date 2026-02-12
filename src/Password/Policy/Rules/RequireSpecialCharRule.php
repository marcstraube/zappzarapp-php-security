<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Policy\Rules;

use Override;
use SensitiveParameter;
use Zappzarapp\Security\Password\Policy\PolicyRule;

/**
 * Require at least one special character
 */
final readonly class RequireSpecialCharRule implements PolicyRule
{
    /**
     * Common special characters
     */
    private const string DEFAULT_SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\`~';

    public function __construct(
        private string $specialChars = self::DEFAULT_SPECIAL_CHARS,
    ) {
    }

    #[Override]
    public function isSatisfied(#[SensitiveParameter] string $password): bool
    {
        for ($i = 0; $i < mb_strlen($password, 'UTF-8'); $i++) {
            $char = mb_substr($password, $i, 1, 'UTF-8');
            if (str_contains($this->specialChars, $char)) {
                return true;
            }
        }

        return false;
    }

    #[Override]
    public function errorMessage(): string
    {
        return 'Password must contain at least one special character';
    }

    /**
     * Get the allowed special characters
     */
    public function specialChars(): string
    {
        return $this->specialChars;
    }
}
