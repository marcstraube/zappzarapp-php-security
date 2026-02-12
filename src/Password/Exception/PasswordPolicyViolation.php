<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when a password violates policy rules
 */
final class PasswordPolicyViolation extends InvalidArgumentException
{
    /**
     * @param list<string> $violations List of policy violations
     */
    public function __construct(
        private readonly array $violations,
    ) {
        parent::__construct('Password does not meet policy requirements: ' . implode(', ', $violations));
    }

    /**
     * Get the list of violations
     *
     * @return list<string>
     */
    public function violations(): array
    {
        return $this->violations;
    }

    /**
     * Create for minimum length violation
     */
    public static function minLength(int $required, int $actual): self
    {
        return new self([sprintf(
            'Password must be at least %d characters (got %d)',
            $required,
            $actual
        )]);
    }

    /**
     * Create for maximum length violation
     */
    public static function maxLength(int $maximum, int $actual): self
    {
        return new self([sprintf(
            'Password must not exceed %d characters (got %d)',
            $maximum,
            $actual
        )]);
    }

    /**
     * Create for missing character class
     */
    public static function missingCharacterClass(string $class): self
    {
        return new self([sprintf('Password must contain at least one %s character', $class)]);
    }

    /**
     * Create for multiple violations
     *
     * @param list<string> $violations
     */
    public static function multiple(array $violations): self
    {
        return new self($violations);
    }
}
