<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Policy\Rules;

use Override;
use SensitiveParameter;
use Zappzarapp\Security\Password\Policy\PolicyRule;

/**
 * Rule that checks password does not contain contextual information
 *
 * Prevents users from using their username, email, or other personal
 * information as part of their password.
 *
 * @see https://pages.nist.gov/800-63-3/sp800-63b.html Section 5.1.1.2
 */
final readonly class NoContextRule implements PolicyRule
{
    /**
     * @param list<string> $contextStrings Strings that must not appear in password
     * @param int $minMatchLength Minimum length for context match (default: 3)
     */
    public function __construct(
        private array $contextStrings,
        private int $minMatchLength = 3,
    ) {
    }

    #[Override]
    public function isSatisfied(#[SensitiveParameter] string $password): bool
    {
        if ($password === '') {
            return true;
        }

        $lowerPassword = mb_strtolower($password, 'UTF-8');

        foreach ($this->contextStrings as $context) {
            if (mb_strlen($context, 'UTF-8') < $this->minMatchLength) {
                continue;
            }

            $lowerContext = mb_strtolower($context, 'UTF-8');

            if (str_contains($lowerPassword, $lowerContext)) {
                return false;
            }
        }

        return true;
    }

    #[Override]
    public function errorMessage(): string
    {
        return 'Password must not contain personal information such as username or email';
    }

    /**
     * Get the context strings being checked
     *
     * @return list<string>
     */
    public function contextStrings(): array
    {
        return $this->contextStrings;
    }

    /**
     * Get the minimum length for context matching
     */
    public function minMatchLength(): int
    {
        return $this->minMatchLength;
    }

    /**
     * Create rule for username context
     */
    public static function forUsername(string $username): self
    {
        return new self([$username]);
    }

    /**
     * Create rule for email context
     *
     * Extracts local part and domain name (without TLD) as context
     */
    public static function forEmail(string $email): self
    {
        $contexts = [];

        $parts = explode('@', $email, 2);
        if ($parts[0] !== '') {
            $contexts[] = $parts[0]; // Local part
        }

        if (count($parts) > 1) {
            // Extract domain name without TLD
            $domainParts = explode('.', $parts[1]);
            if (count($domainParts) > 1) {
                array_pop($domainParts); // Remove TLD
                $contexts[] = implode('.', $domainParts);
            }
        }

        return new self($contexts);
    }

    /**
     * Create rule for multiple context strings
     *
     * @param list<string> $contexts
     */
    public static function forContexts(array $contexts): self
    {
        return new self($contexts);
    }
}
