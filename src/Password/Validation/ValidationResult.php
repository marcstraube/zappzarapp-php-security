<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Validation;

use Zappzarapp\Security\Password\Strength\StrengthLevel;

/**
 * Password validation result
 */
final readonly class ValidationResult
{
    /**
     * @param bool $isValid Whether the password is valid
     * @param list<string> $violations List of policy violations
     * @param StrengthLevel|null $strength Password strength level
     * @param float|null $entropy Password entropy in bits
     * @param int|null $pwnedCount Number of breach occurrences (null if not checked)
     */
    public function __construct(
        public bool $isValid,
        public array $violations = [],
        public ?StrengthLevel $strength = null,
        public ?float $entropy = null,
        public ?int $pwnedCount = null,
    ) {
    }

    /**
     * Create a valid result
     */
    public static function valid(
        ?StrengthLevel $strength = null,
        ?float $entropy = null,
        ?int $pwnedCount = null,
    ): self {
        return new self(true, [], $strength, $entropy, $pwnedCount);
    }

    /**
     * Create an invalid result
     *
     * @param list<string> $violations
     */
    public static function invalid(
        array $violations,
        ?StrengthLevel $strength = null,
        ?float $entropy = null,
        ?int $pwnedCount = null,
    ): self {
        return new self(false, $violations, $strength, $entropy, $pwnedCount);
    }

    /**
     * Check if password passed all checks
     */
    public function passed(): bool
    {
        return $this->isValid;
    }

    /**
     * Check if password failed any check
     */
    public function failed(): bool
    {
        return !$this->isValid;
    }

    /**
     * Check if password was found in breaches
     */
    public function isPwned(): bool
    {
        return $this->pwnedCount !== null && $this->pwnedCount > 0;
    }
}
