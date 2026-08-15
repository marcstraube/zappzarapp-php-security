<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp;

use Zappzarapp\Security\Totp\Exception\InvalidTotpConfigException;

/**
 * Immutable TOTP configuration
 *
 * Defaults follow RFC 6238 and the de-facto authenticator-app standard:
 * 30-second period, 6 digits, SHA-1, verification window of ±1 step.
 * Wider windows weaken replay resistance and must be opted into
 * explicitly via withWindow().
 *
 * ## Usage
 *
 * ```php
 * $config = new TotpConfig();                        // 30s / 6 digits / SHA-1 / ±1
 * $config = new TotpConfig()->withDigits(8)->withAlgorithm(TotpAlgorithm::Sha256);
 * ```
 */
final readonly class TotpConfig
{
    /**
     * @param int $period Time-step length in seconds (15 to 300)
     * @param int $digits Code length (6 to 8)
     * @param TotpAlgorithm $algorithm HMAC hash algorithm
     * @param int $window Verification window in steps each direction (0 to 10)
     *
     * @throws InvalidTotpConfigException If a value is out of range
     */
    public function __construct(
        public int $period = 30,
        public int $digits = 6,
        public TotpAlgorithm $algorithm = TotpAlgorithm::Sha1,
        public int $window = 1,
    ) {
        if ($this->period < 15 || $this->period > 300) {
            throw InvalidTotpConfigException::invalidPeriod($this->period);
        }

        if ($this->digits < 6 || $this->digits > 8) {
            throw InvalidTotpConfigException::invalidDigits($this->digits);
        }

        if ($this->window < 0 || $this->window > 10) {
            throw InvalidTotpConfigException::invalidWindow($this->window);
        }
    }

    /**
     * Create a copy with a different time-step period
     *
     * @throws InvalidTotpConfigException If the period is out of range
     */
    public function withPeriod(int $period): self
    {
        return new self($period, $this->digits, $this->algorithm, $this->window);
    }

    /**
     * Create a copy with a different code length
     *
     * @throws InvalidTotpConfigException If the digit count is out of range
     */
    public function withDigits(int $digits): self
    {
        return new self($this->period, $digits, $this->algorithm, $this->window);
    }

    /**
     * Create a copy with a different HMAC hash algorithm
     */
    public function withAlgorithm(TotpAlgorithm $algorithm): self
    {
        return new self($this->period, $this->digits, $algorithm, $this->window);
    }

    /**
     * Create a copy with a different verification window
     *
     * @throws InvalidTotpConfigException If the window is out of range
     */
    public function withWindow(int $window): self
    {
        return new self($this->period, $this->digits, $this->algorithm, $window);
    }
}
