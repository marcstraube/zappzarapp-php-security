<?php

/**
 * @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive
 * @noinspection PhpAttributeCanBeAddedToOverriddenMemberInspection All implementations already have the attribute
 */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Policy;

use SensitiveParameter;

/**
 * Interface for password policy rules
 */
interface PolicyRule
{
    /**
     * Check if the password satisfies this rule
     *
     * @param string $password The password to check
     */
    public function isSatisfied(#[SensitiveParameter] string $password): bool;

    /**
     * Get the error message for violation
     */
    public function errorMessage(): string;
}
