<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Password\Strength;

/**
 * Character set definitions for password entropy calculation
 *
 * Defines the size of character pools used in entropy calculations,
 * regex patterns for character type detection, and entropy thresholds.
 *
 * Entropy thresholds are aligned with NIST SP 800-63B recommendations:
 * - Minimum 80 bits for STRONG passwords
 * - 128+ bits for VERY_STRONG (cryptographic key strength)
 *
 * @see https://pages.nist.gov/800-63-3/sp800-63b.html
 */
final class CharacterSet
{
    /**
     * Entropy threshold for VERY_WEAK passwords (bits)
     *
     * Passwords below this threshold can be cracked in seconds.
     */
    public const float ENTROPY_VERY_WEAK = 28.0;

    /**
     * Entropy threshold for WEAK passwords (bits)
     *
     * Can be cracked with moderate resources (hours to days).
     */
    public const float ENTROPY_WEAK = 36.0;

    /**
     * Entropy threshold for FAIR passwords (bits)
     *
     * Provides basic protection but below NIST recommendations.
     */
    public const float ENTROPY_FAIR = 60.0;

    /**
     * Entropy threshold for STRONG passwords (bits)
     *
     * Meets NIST SP 800-63B minimum recommendations (80+ bits).
     * Provides good protection for most use cases.
     */
    public const float ENTROPY_STRONG = 80.0;

    /**
     * Size of lowercase letter pool (a-z)
     */
    public const int LOWERCASE_SIZE = 26;

    /**
     * Size of uppercase letter pool (A-Z)
     */
    public const int UPPERCASE_SIZE = 26;

    /**
     * Size of digit pool (0-9)
     */
    public const int DIGITS_SIZE = 10;

    /**
     * Size of common special character pool
     * Includes: !@#$%^&*()_+-=[]{}|;:'",.<>?/\`~
     */
    public const int SPECIAL_SIZE = 32;

    /**
     * Size of space character pool
     */
    public const int SPACE_SIZE = 1;

    /**
     * Estimated size of extended ASCII/Unicode character pool
     * Conservative estimate for characters beyond ASCII
     */
    public const int EXTENDED_SIZE = 100;

    /**
     * Regex pattern for detecting common special characters
     */
    public const string SPECIAL_PATTERN = '/[!@#$%^&*()_+\-=\[\]{}|;:\'",.<>?\/\\\\`~]/';

    /**
     * Regex pattern for detecting lowercase letters (Unicode-aware)
     */
    public const string LOWERCASE_PATTERN = '/\p{Ll}/u';

    /**
     * Regex pattern for detecting uppercase letters (Unicode-aware)
     */
    public const string UPPERCASE_PATTERN = '/\p{Lu}/u';

    /**
     * Regex pattern for detecting digits
     */
    public const string DIGITS_PATTERN = '/\d/';

    /**
     * Regex pattern for detecting extended ASCII/Unicode characters
     */
    public const string EXTENDED_PATTERN = '/[^\x00-\x7F]/';

    /**
     * Prevent instantiation (constants-only class)
     *
     * @codeCoverageIgnore Private constructor prevents instantiation
     */
    private function __construct()
    {
    }
}
