<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Strength;

use SensitiveParameter;
use Zappzarapp\Security\Password\Security\ClearsMemory;

/**
 * Password strength meter
 *
 * Analyzes password strength based on entropy and patterns.
 */
final readonly class PasswordStrengthMeter
{
    use ClearsMemory;

    private EntropyCalculator $calculator;

    public function __construct()
    {
        $this->calculator = new EntropyCalculator();
    }

    /**
     * Measure password strength
     *
     * @return array{level: StrengthLevel, entropy: float, feedback: list<string>}
     */
    public function measure(#[SensitiveParameter] string $password): array
    {
        return $this->withClearedMemory($password, function (string $pwd): array {
            $entropy  = $this->calculator->calculate($pwd);
            $level    = $this->calculator->strengthLevel($pwd);
            $feedback = $this->generateFeedback($pwd, $level);

            return [
                'level'    => $level,
                'entropy'  => $entropy,
                'feedback' => $feedback,
            ];
        });
    }

    /**
     * Get the strength level
     */
    public function level(#[SensitiveParameter] string $password): StrengthLevel
    {
        return $this->withClearedMemory($password, fn(string $pwd): StrengthLevel => $this->calculator->strengthLevel($pwd));
    }

    /**
     * Get entropy in bits
     */
    public function entropy(#[SensitiveParameter] string $password): float
    {
        return $this->withClearedMemory($password, fn(string $pwd): float => $this->calculator->calculate($pwd));
    }

    /**
     * Check if password meets minimum strength requirement
     */
    public function meetsMinimum(#[SensitiveParameter] string $password, StrengthLevel $minimum): bool
    {
        return $this->withClearedMemory($password, fn(string $pwd): bool => $this->level($pwd)->meetsMinimum($minimum));
    }

    /**
     * Generate feedback for password improvement
     *
     * @return list<string>
     */
    private function generateFeedback(#[SensitiveParameter] string $password, StrengthLevel $level): array
    {
        $feedback = [];

        if ($level->score() >= StrengthLevel::STRONG->score()) {
            return $feedback;
        }

        $length = mb_strlen($password, 'UTF-8');

        // Length feedback
        if ($length < 12) {
            $feedback[] = 'Use at least 12 characters';
        } elseif ($length < 16) {
            $feedback[] = 'Consider using more characters for better security';
        }

        // Character diversity feedback
        if (preg_match(CharacterSet::UPPERCASE_PATTERN, $password) !== 1) {
            $feedback[] = 'Add uppercase letters';
        }

        if (preg_match(CharacterSet::LOWERCASE_PATTERN, $password) !== 1) {
            $feedback[] = 'Add lowercase letters';
        }

        if (preg_match(CharacterSet::DIGITS_PATTERN, $password) !== 1) {
            $feedback[] = 'Add numbers';
        }

        if (preg_match(CharacterSet::SPECIAL_PATTERN, $password) !== 1) {
            $feedback[] = 'Add special characters';
        }

        // Pattern detection
        if ($this->hasRepeatingPattern($password)) {
            $feedback[] = 'Avoid repeating patterns';
        }

        if ($this->hasSequentialPattern($password)) {
            $feedback[] = 'Avoid sequential characters';
        }

        return $feedback;
    }

    /**
     * Check for repeating patterns like "abcabc"
     */
    private function hasRepeatingPattern(#[SensitiveParameter] string $password): bool
    {
        $length = mb_strlen($password, 'UTF-8');

        // Check for patterns up to half the password length
        for ($patternLength = 2; $patternLength <= (int) ($length / 2); $patternLength++) {
            $pattern  = mb_substr($password, 0, $patternLength, 'UTF-8');
            $repeated = str_repeat($pattern, (int) ceil($length / $patternLength));
            $repeated = mb_substr($repeated, 0, $length, 'UTF-8');

            if ($password === $repeated) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for sequential patterns like "12345" or "abcde"
     */
    private function hasSequentialPattern(#[SensitiveParameter] string $password): bool
    {
        $length = mb_strlen($password, 'UTF-8');

        if ($length < 4) {
            return false;
        }

        $sequentialCount = 0;
        $prevChar        = '';

        for ($i = 0; $i < $length; $i++) {
            $char = mb_substr($password, $i, 1, 'UTF-8');

            if ($prevChar !== '' && ord($char) === ord($prevChar) + 1) {
                $sequentialCount++;
                if ($sequentialCount >= 3) {
                    return true;
                }
            } else {
                $sequentialCount = 0;
            }

            $prevChar = $char;
        }

        return false;
    }
}
