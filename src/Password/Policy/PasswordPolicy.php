<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive
 * @noinspection PhpParenthesesCanBeOmittedForNewCallInspection PHPMD/PDepend cannot parse new Foo()->method() syntax
 */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Policy;

use SensitiveParameter;
use Zappzarapp\Security\Password\Policy\Rules\MaxLengthRule;
use Zappzarapp\Security\Password\Policy\Rules\MinLengthRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireDigitRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireLowercaseRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireSpecialCharRule;
use Zappzarapp\Security\Password\Policy\Rules\RequireUppercaseRule;

/**
 * Immutable password policy configuration
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
 */
final readonly class PasswordPolicy
{
    /**
     * @param list<PolicyRule> $rules List of rules to enforce
     */
    public function __construct(
        private array $rules = [],
    ) {
    }

    /**
     * Add a rule to the policy
     */
    public function withRule(PolicyRule $rule): self
    {
        $newRules   = $this->rules;
        $newRules[] = $rule;

        return new self($newRules);
    }

    /**
     * Get all rules
     *
     * @return list<PolicyRule>
     */
    public function rules(): array
    {
        return $this->rules;
    }

    /**
     * Check if password satisfies all rules
     *
     * @return list<string> List of violation messages (empty if valid)
     */
    public function validate(#[SensitiveParameter] string $password): array
    {
        $violations = [];

        foreach ($this->rules as $rule) {
            if (!$rule->isSatisfied($password)) {
                $violations[] = $rule->errorMessage();
            }
        }

        return $violations;
    }

    /**
     * Check if password is valid
     */
    public function isValid(#[SensitiveParameter] string $password): bool
    {
        return $this->validate($password) === [];
    }

    /**
     * Create NIST-compliant policy (recommended)
     *
     * Based on NIST SP 800-63B guidelines:
     * - Minimum 8 characters (we use 12 for extra security)
     * - Maximum 128 characters
     * - No character class requirements (they reduce entropy)
     *
     * @see https://pages.nist.gov/800-63-3/sp800-63b.html
     */
    public static function nist(): self
    {
        return (new self())
            ->withRule(new MinLengthRule(12))
            ->withRule(new MaxLengthRule(128));
    }

    /**
     * Create strict policy (traditional requirements)
     *
     * Includes character class requirements.
     * Note: NIST recommends against these, but some compliance frameworks require them.
     */
    public static function strict(): self
    {
        return (new self())
            ->withRule(new MinLengthRule(12))
            ->withRule(new MaxLengthRule(128))
            ->withRule(new RequireUppercaseRule())
            ->withRule(new RequireLowercaseRule())
            ->withRule(new RequireDigitRule())
            ->withRule(new RequireSpecialCharRule());
    }

    /**
     * Create legacy policy (basic requirements)
     */
    public static function legacy(): self
    {
        return (new self())
            ->withRule(new MinLengthRule(8))
            ->withRule(new MaxLengthRule(72)); // bcrypt limit
    }

    /**
     * Create empty policy (no restrictions)
     */
    public static function empty(): self
    {
        return new self();
    }
}
