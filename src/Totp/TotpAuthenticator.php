<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Native PHP 8.2 attribute, stubs cause false positive */

declare(strict_types=1);

namespace Zappzarapp\Security\Totp;

use Psr\Clock\ClockInterface;
use SensitiveParameter;
use Zappzarapp\Security\Totp\Exception\InvalidTotpConfigException;
use Zappzarapp\Security\Totp\Hotp\HotpGenerator;

/**
 * Time-based one-time password generation and verification per RFC 6238
 *
 * Secure by design:
 *
 * - Codes are compared with hash_equals(), and every candidate step in
 *   the window is evaluated - no early exit on match
 * - Replay protection: pass the persisted last accepted time step and
 *   codes for that step (or older) are rejected; persist
 *   TotpVerificationResult::$matchedTimeStep after each success
 * - Malformed user input (wrong length, non-digits) is rejected without
 *   ever touching the secret
 *
 * ## Usage
 *
 * ```php
 * $totp   = new TotpAuthenticator();
 * $secret = TotpSecret::generate();
 *
 * $result = $totp->verify($secret, $submittedCode, lastAcceptedTimeStep: $user->lastTotpStep);
 *
 * if ($result->valid) {
 *     $user->lastTotpStep = $result->matchedTimeStep; // persist - blocks replay
 * }
 * ```
 */
final readonly class TotpAuthenticator
{
    public function __construct(
        private TotpConfig $config = new TotpConfig(),
        private ?ClockInterface $clock = null,
        private HotpGenerator $hotp = new HotpGenerator(),
    ) {
    }

    /**
     * Generate the code for a point in time
     *
     * @param TotpSecret $secret The shared secret
     * @param int|null $timestamp Unix timestamp; null uses the injected clock or system time
     *
     * @throws InvalidTotpConfigException If the timestamp is negative
     */
    public function generateCode(TotpSecret $secret, ?int $timestamp = null): string
    {
        return $this->hotp->generate(
            $secret,
            $this->timeStep($timestamp ?? $this->now()),
            $this->config->digits,
            $this->config->algorithm
        );
    }

    /**
     * Verify a user-submitted code within the configured window
     *
     * All candidate steps are checked with constant-time comparison.
     * Steps at or before $lastAcceptedTimeStep are skipped, so a code
     * can never be accepted twice (replay protection) - persist
     * matchedTimeStep after each successful verification. If a code
     * happens to be valid for more than one step in the window, the
     * latest step wins: it advances the replay barrier the furthest.
     *
     * @param TotpSecret $secret The shared secret
     * @param string $code The user-submitted code
     * @param int|null $lastAcceptedTimeStep Persisted step of the last accepted code
     * @param int|null $timestamp Unix timestamp; null uses the injected clock or system time
     *
     * @throws InvalidTotpConfigException If the timestamp is negative
     */
    public function verify(
        TotpSecret $secret,
        #[SensitiveParameter]
        string $code,
        ?int $lastAcceptedTimeStep = null,
        ?int $timestamp = null,
    ): TotpVerificationResult {
        if (!$this->hasValidFormat($code)) {
            return TotpVerificationResult::invalid();
        }

        $currentStep = $this->timeStep($timestamp ?? $this->now());
        $matchedStep = null;

        for ($step = $currentStep - $this->config->window; $step <= $currentStep + $this->config->window; $step++) {
            if ($step < 0) {
                continue;
            }

            if ($lastAcceptedTimeStep !== null && $step <= $lastAcceptedTimeStep) {
                continue;
            }

            $expected = $this->hotp->generate($secret, $step, $this->config->digits, $this->config->algorithm);

            if (hash_equals($expected, $code)) {
                $matchedStep = $step;
            }
        }

        if ($matchedStep === null) {
            return TotpVerificationResult::invalid();
        }

        return TotpVerificationResult::valid($matchedStep);
    }

    /**
     * Map a Unix timestamp to its RFC 6238 time step
     *
     * @throws InvalidTotpConfigException If the timestamp is negative
     */
    private function timeStep(int $timestamp): int
    {
        if ($timestamp < 0) {
            throw InvalidTotpConfigException::invalidTimestamp($timestamp);
        }

        return intdiv($timestamp, $this->config->period);
    }

    /**
     * Check length and digit-only content without touching the secret
     */
    private function hasValidFormat(string $code): bool
    {
        return strlen($code) === $this->config->digits && ctype_digit($code);
    }

    /**
     * Current Unix timestamp from the injected clock or system time
     */
    private function now(): int
    {
        if (!$this->clock instanceof ClockInterface) {
            return time();
        }

        return $this->clock->now()->getTimestamp();
    }
}
