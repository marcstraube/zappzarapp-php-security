<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Policy\Rules;

use Override;
use SensitiveParameter;
use Zappzarapp\Security\Password\Policy\PolicyRule;

/**
 * Maximum password length rule
 *
 * Prevents DoS attacks via extremely long passwords (bcrypt has 72-byte limit).
 */
final readonly class MaxLengthRule implements PolicyRule
{
    public function __construct(
        private int $maxLength = 128,
    ) {
    }

    #[Override]
    public function isSatisfied(#[SensitiveParameter] string $password): bool
    {
        return mb_strlen($password, 'UTF-8') <= $this->maxLength;
    }

    #[Override]
    public function errorMessage(): string
    {
        return sprintf('Password must not exceed %d characters', $this->maxLength);
    }

    /**
     * Get the maximum length
     */
    public function maxLength(): int
    {
        return $this->maxLength;
    }
}
