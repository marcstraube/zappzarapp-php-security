<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Policy\Rules;

use Override;
use SensitiveParameter;
use Zappzarapp\Security\Password\Policy\PolicyRule;

/**
 * Minimum password length rule
 */
final readonly class MinLengthRule implements PolicyRule
{
    public function __construct(
        private int $minLength = 12,
    ) {
    }

    #[Override]
    public function isSatisfied(#[SensitiveParameter] string $password): bool
    {
        return mb_strlen($password, 'UTF-8') >= $this->minLength;
    }

    #[Override]
    public function errorMessage(): string
    {
        return sprintf('Password must be at least %d characters', $this->minLength);
    }

    /**
     * Get the minimum length
     */
    public function minLength(): int
    {
        return $this->minLength;
    }
}
