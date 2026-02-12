<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Policy\Rules;

use Override;
use SensitiveParameter;
use Zappzarapp\Security\Password\Policy\PolicyRule;

/**
 * Require at least one uppercase letter
 *
 * Note: This pattern is intentionally duplicated from CharacterSet::UPPERCASE_PATTERN
 * in the PasswordStrength layer. The duplication is by design due to Deptrac
 * architecture boundaries: PasswordPolicy cannot depend on PasswordStrength.
 * Both patterns use Unicode property \p{Lu} for full Unicode uppercase support.
 *
 * @see \Zappzarapp\Security\Password\Strength\CharacterSet::UPPERCASE_PATTERN
 */
final readonly class RequireUppercaseRule implements PolicyRule
{
    /** @see CharacterSet::UPPERCASE_PATTERN for the equivalent pattern in PasswordStrength */
    private const string PATTERN = '/\p{Lu}/u';

    #[Override]
    public function isSatisfied(#[SensitiveParameter] string $password): bool
    {
        return preg_match(self::PATTERN, $password) === 1;
    }

    #[Override]
    public function errorMessage(): string
    {
        return 'Password must contain at least one uppercase letter';
    }
}
