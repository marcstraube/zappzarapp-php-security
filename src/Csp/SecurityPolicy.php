<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csp;

/**
 * CSP Security Policy Levels
 *
 * Defines which unsafe-* directives are allowed.
 * Follows security-by-default principle with explicit opt-in for permissive policies.
 *
 * @psalm-api
 */
enum SecurityPolicy
{
    /**
     * Strict CSP
     *
     * No unsafe-eval, no unsafe-inline.
     * Nonce-based script and style loading only.
     * Recommended for production environments.
     */
    case STRICT;

    /**
     * Lenient CSP
     *
     * Allows both unsafe-eval and unsafe-inline.
     * Use when nonce-based approach is not feasible or during initial development.
     */
    case LENIENT;

    /**
     * Allow unsafe-eval only
     *
     * Required by some legacy frameworks (Vue 2, older Angular) that use eval().
     * Still enforces nonce-based inline scripts/styles.
     */
    case UNSAFE_EVAL;

    /**
     * Allow unsafe-inline only
     *
     * Rare use case where inline styles/scripts cannot use nonces.
     * Significantly weakens XSS protection - avoid if possible.
     */
    case UNSAFE_INLINE;

    /**
     * Check if unsafe-eval is allowed
     */
    public function allowsUnsafeEval(): bool
    {
        return match ($this) {
            self::LENIENT, self::UNSAFE_EVAL => true,
            default                          => false,
        };
    }

    /**
     * Check if unsafe-inline is allowed
     */
    public function allowsUnsafeInline(): bool
    {
        return match ($this) {
            self::LENIENT, self::UNSAFE_INLINE => true,
            default                            => false,
        };
    }
}
