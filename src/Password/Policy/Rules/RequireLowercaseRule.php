<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Policy\Rules;

use Override;
use SensitiveParameter;
use Zappzarapp\Security\Password\Policy\PolicyRule;

/**
 * Require at least one lowercase letter
 *
 * Note: This pattern is intentionally duplicated from CharacterSet::LOWERCASE_PATTERN
 * in the PasswordStrength layer. The duplication is by design due to Deptrac
 * architecture boundaries: PasswordPolicy cannot depend on PasswordStrength.
 * Both patterns use Unicode property \p{Ll} for full Unicode lowercase support.
 *
 * @see \Zappzarapp\Security\Password\Strength\CharacterSet::LOWERCASE_PATTERN
 */
final readonly class RequireLowercaseRule implements PolicyRule
{
    /** @see CharacterSet::LOWERCASE_PATTERN for the equivalent pattern in PasswordStrength */
    private const string PATTERN = '/\p{Ll}/u';

    #[Override]
    public function isSatisfied(#[SensitiveParameter] string $password): bool
    {
        return preg_match(self::PATTERN, $password) === 1;
    }

    #[Override]
    public function errorMessage(): string
    {
        return 'Password must contain at least one lowercase letter';
    }
}
