<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Strength;

use SensitiveParameter;

/**
 * Password entropy calculator
 *
 * Calculates entropy based on character pool size.
 */
final readonly class EntropyCalculator
{
    /**
     * Calculate entropy in bits
     *
     * @param string $password The password to analyze
     */
    public function calculate(#[SensitiveParameter] string $password): float
    {
        if ($password === '') {
            return 0.0;
        }

        $poolSize = $this->calculatePoolSize($password);
        $length   = mb_strlen($password, 'UTF-8');

        if ($poolSize === 0) {
            return 0.0;
        }

        // Entropy = log2(poolSize^length) = length * log2(poolSize)
        return (float) $length * log($poolSize, 2);
    }

    /**
     * Determine the strength level based on entropy
     */
    public function strengthLevel(#[SensitiveParameter] string $password): StrengthLevel
    {
        $entropy = $this->calculate($password);

        return match (true) {
            $entropy < CharacterSet::ENTROPY_VERY_WEAK => StrengthLevel::VERY_WEAK,
            $entropy < CharacterSet::ENTROPY_WEAK      => StrengthLevel::WEAK,
            $entropy < CharacterSet::ENTROPY_FAIR      => StrengthLevel::FAIR,
            $entropy < CharacterSet::ENTROPY_STRONG    => StrengthLevel::STRONG,
            default                                    => StrengthLevel::VERY_STRONG,
        };
    }

    /**
     * Calculate the character pool size based on used character types
     */
    private function calculatePoolSize(#[SensitiveParameter] string $password): int
    {
        $poolSize = 0;

        if (preg_match(CharacterSet::LOWERCASE_PATTERN, $password) === 1) {
            $poolSize += CharacterSet::LOWERCASE_SIZE;
        }

        if (preg_match(CharacterSet::UPPERCASE_PATTERN, $password) === 1) {
            $poolSize += CharacterSet::UPPERCASE_SIZE;
        }

        if (preg_match(CharacterSet::DIGITS_PATTERN, $password) === 1) {
            $poolSize += CharacterSet::DIGITS_SIZE;
        }

        if (preg_match(CharacterSet::SPECIAL_PATTERN, $password) === 1) {
            $poolSize += CharacterSet::SPECIAL_SIZE;
        }

        if (str_contains($password, ' ')) {
            $poolSize += CharacterSet::SPACE_SIZE;
        }

        if (preg_match(CharacterSet::EXTENDED_PATTERN, $password) === 1) {
            $poolSize += CharacterSet::EXTENDED_SIZE;
        }

        return $poolSize;
    }
}
