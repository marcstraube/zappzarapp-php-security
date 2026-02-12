<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Validation;

use Override;
use SensitiveParameter;
use Zappzarapp\Security\Password\Policy\PasswordPolicy;
use Zappzarapp\Security\Password\Pwned\HttpClientInterface;
use Zappzarapp\Security\Password\Pwned\PwnedPasswordChecker;
use Zappzarapp\Security\Password\Strength\PasswordStrengthMeter;
use Zappzarapp\Security\Password\Strength\StrengthLevel;

/**
 * Default password validator
 *
 * Combines policy rules, strength meter, and HIBP checking.
 */
final readonly class DefaultPasswordValidator implements PasswordValidator
{
    private PasswordStrengthMeter $strengthMeter;

    public function __construct(
        private PasswordPolicy $policy = new PasswordPolicy(),
        private ?PwnedPasswordChecker $pwnedChecker = null,
        private ?StrengthLevel $minimumStrength = null,
    ) {
        $this->strengthMeter = new PasswordStrengthMeter();
    }

    #[Override]
    public function validate(#[SensitiveParameter] string $password): ValidationResult
    {
        $violations = [];

        // Check policy rules
        $policyViolations = $this->policy->validate($password);
        $violations       = [...$violations, ...$policyViolations];

        // Calculate strength
        $strength = $this->strengthMeter->level($password);
        $entropy  = $this->strengthMeter->entropy($password);

        // Check minimum strength
        if ($this->minimumStrength instanceof StrengthLevel && !$strength->meetsMinimum($this->minimumStrength)) {
            $violations[] = sprintf(
                'Password strength must be at least %s (got %s)',
                $this->minimumStrength->label(),
                $strength->label()
            );
        }

        // Check HIBP
        $pwnedCount = null;
        if ($this->pwnedChecker instanceof PwnedPasswordChecker) {
            $pwnedCount = $this->pwnedChecker->check($password);
            if ($pwnedCount > 0) {
                $violations[] = sprintf(
                    'Password has been exposed in %d data breach%s',
                    $pwnedCount,
                    $pwnedCount === 1 ? '' : 'es'
                );
            }
        }

        if ($violations === []) {
            return ValidationResult::valid($strength, $entropy, $pwnedCount);
        }

        return ValidationResult::invalid($violations, $strength, $entropy, $pwnedCount);
    }

    /**
     * Create with NIST policy
     */
    public static function nist(): self
    {
        return new self(PasswordPolicy::nist());
    }

    /**
     * Create with strict policy and HIBP checking
     */
    public static function strict(?PwnedPasswordChecker $pwnedChecker = null): self
    {
        return new self(
            PasswordPolicy::strict(),
            $pwnedChecker,
            StrengthLevel::FAIR
        );
    }

    /**
     * Create with HIBP checking
     */
    public static function withPwnedCheck(
        HttpClientInterface $client,
        PasswordPolicy $policy = new PasswordPolicy(),
    ): self {
        return new self($policy, new PwnedPasswordChecker($client));
    }
}
