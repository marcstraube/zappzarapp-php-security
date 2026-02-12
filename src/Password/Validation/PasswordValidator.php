<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Validation;

use SensitiveParameter;

/**
 * Interface for password validators
 */
interface PasswordValidator
{
    /**
     * Validate a password
     *
     * @param string $password The password to validate
     */
    public function validate(#[SensitiveParameter] string $password): ValidationResult;
}
