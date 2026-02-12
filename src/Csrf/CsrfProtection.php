<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Psalm stubs conflict with native PHP 8.2 SensitiveParameter */

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf;

use Random\RandomException;
use RuntimeException;
use SensitiveParameter;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Pattern\DoubleSubmitCookiePattern;
use Zappzarapp\Security\Csrf\Pattern\SynchronizerTokenPattern;
use Zappzarapp\Security\Csrf\Storage\CsrfStorageInterface;
use Zappzarapp\Security\Csrf\Token\CsrfToken;

/**
 * Main CSRF protection facade
 *
 * Provides a simple interface for CSRF protection using either
 * Synchronizer Token Pattern or Double Submit Cookie Pattern.
 *
 * ## Basic Usage (Synchronizer Token Pattern)
 *
 * ```php
 * $storage = new SessionCsrfStorage();
 * $csrf = CsrfProtection::synchronizer($storage);
 *
 * // In your form
 * echo $csrf->field();
 *
 * // On form submission
 * $csrf->validate($_POST['_csrf_token']);
 * ```
 *
 * ## SPA Usage (HMAC-Signed Double Submit Cookie Pattern)
 *
 * ```php
 * $secret = getenv('CSRF_SECRET'); // Min 32 bytes
 * $csrf = CsrfProtection::doubleSubmit($secret);
 *
 * // On first request, set cookie with raw token
 * $token = $csrf->token();
 * setcookie('csrf_token', $token->value(), $csrf->cookieOptions());
 *
 * // Include signed token in response (for JS to include in headers)
 * echo json_encode(['csrfToken' => $csrf->signToken($token)]);
 *
 * // On subsequent requests, validate cookie + signed header
 * $csrf->validateDoubleSubmit($_COOKIE['csrf_token'], getHeader('X-CSRF-Token'));
 * ```
 */
final class CsrfProtection
{
    private ?SynchronizerTokenPattern $synchronizer  = null;

    private ?DoubleSubmitCookiePattern $doubleSubmit = null;

    /**
     * @param CsrfStorageInterface|null $storage Storage for synchronizer pattern
     * @param CsrfConfig $config CSRF configuration
     * @param string|null $secret Secret for double-submit HMAC signing (min 32 bytes)
     */
    public function __construct(
        private readonly ?CsrfStorageInterface $storage = null,
        private readonly CsrfConfig $config = new CsrfConfig(),
        #[SensitiveParameter] private readonly ?string $secret = null,
    ) {
    }

    /**
     * Create with Synchronizer Token Pattern
     */
    public static function synchronizer(
        CsrfStorageInterface $storage,
        CsrfConfig $config = new CsrfConfig(),
    ): self {
        return new self($storage, $config);
    }

    /**
     * Create with HMAC-Signed Double Submit Cookie Pattern
     *
     * @param string $secret Server-side secret for HMAC signing (min 32 bytes)
     * @param CsrfConfig $config CSRF configuration
     */
    public static function doubleSubmit(
        #[SensitiveParameter] string $secret,
        CsrfConfig $config = new CsrfConfig(),
    ): self {
        return new self(null, $config, $secret);
    }

    /**
     * Get the current CSRF token
     *
     * For Synchronizer Pattern, retrieves or generates a session token.
     * For Double Submit, generates a new token (caller must store in cookie).
     *
     * @throws RandomException If no suitable random source is available
     */
    public function token(): CsrfToken
    {
        if ($this->storage instanceof CsrfStorageInterface) {
            return $this->getSynchronizer()->getToken();
        }

        return $this->getDoubleSubmit()->generateToken();
    }

    /**
     * Generate a hidden form field with the token
     *
     * Only works with Synchronizer Token Pattern.
     *
     * @throws RandomException If no suitable random source is available
     */
    public function field(): string
    {
        return $this->getSynchronizer()->field();
    }

    /**
     * Validate a token (Synchronizer Pattern)
     *
     * @param string $submittedToken The token from the request
     *
     * @throws CsrfTokenMismatchException If validation fails
     * @throws InvalidCsrfTokenException If token format is invalid
     * @throws RandomException If rotation is enabled and random source unavailable
     */
    public function validate(string $submittedToken): void
    {
        $this->getSynchronizer()->validate($submittedToken);
    }

    /**
     * Validate double-submit tokens
     *
     * @param string $cookieToken Token from the cookie
     * @param string $submittedToken Token from header or body
     *
     * @throws CsrfTokenMismatchException If tokens don't match
     * @throws InvalidCsrfTokenException If token format is invalid
     */
    public function validateDoubleSubmit(string $cookieToken, string $submittedToken): void
    {
        $this->getDoubleSubmit()->validate($cookieToken, $submittedToken);
    }

    /**
     * Check if a token is valid (Synchronizer Pattern)
     *
     * @param string $submittedToken The token from the request
     */
    public function isValid(string $submittedToken): bool
    {
        return $this->getSynchronizer()->isValid($submittedToken);
    }

    /**
     * Check if double-submit tokens are valid
     *
     * @param string $cookieToken Token from the cookie
     * @param string $submittedToken Token from header or body
     */
    public function isValidDoubleSubmit(string $cookieToken, string $submittedToken): bool
    {
        return $this->getDoubleSubmit()->isValid($cookieToken, $submittedToken);
    }

    /**
     * Regenerate the token (Synchronizer Pattern)
     *
     * Call after successful login to help prevent session fixation.
     *
     * IMPORTANT: This only regenerates the CSRF token, NOT the PHP session ID.
     * For complete session fixation protection, your application should also call:
     *
     * ```php
     * // After successful authentication:
     * session_regenerate_id(true);  // Regenerate session ID
     * $csrf->regenerate();           // Regenerate CSRF token
     * ```
     *
     * Session ID regeneration is the application's responsibility because:
     * - This library is framework-agnostic
     * - Different frameworks handle sessions differently (Symfony, Laravel, etc.)
     * - Session management may involve additional application-specific logic
     *
     * @throws RandomException If no suitable random source is available
     */
    public function regenerate(): CsrfToken
    {
        return $this->getSynchronizer()->regenerate();
    }

    /**
     * Sign a token for double-submit pattern
     *
     * Returns the HMAC-signed token string to include in forms/headers.
     *
     * @param CsrfToken $token The token to sign
     *
     * @return string Signed token string (token.signature)
     */
    public function signToken(CsrfToken $token): string
    {
        return $this->getDoubleSubmit()->signToken($token);
    }

    /**
     * Get cookie options for double-submit pattern
     *
     * @param bool $secure Use Secure flag (set true in production)
     *
     * @return array{name: string, expires: int, path: string, secure: bool, httponly: bool, samesite: string}
     */
    public function cookieOptions(bool $secure = true): array
    {
        return $this->getDoubleSubmit()->cookieOptions($secure);
    }

    /**
     * Get the form field name
     */
    public function fieldName(): string
    {
        return $this->config->fieldName;
    }

    /**
     * Get the header name
     */
    public function headerName(): string
    {
        return $this->config->headerName;
    }

    /**
     * Get the cookie name
     */
    public function cookieName(): string
    {
        return $this->config->cookieName;
    }

    /**
     * Clear the stored token (Synchronizer Pattern only)
     */
    public function clear(): void
    {
        $this->getSynchronizer()->clear();
    }

    /**
     * Get or create Synchronizer Token Pattern instance
     */
    private function getSynchronizer(): SynchronizerTokenPattern
    {
        if (!$this->synchronizer instanceof SynchronizerTokenPattern) {
            if (!$this->storage instanceof CsrfStorageInterface) {
                throw new RuntimeException(
                    'Storage is required for Synchronizer Token Pattern. ' .
                    'Use CsrfProtection::synchronizer() factory method.'
                );
            }

            $this->synchronizer = new SynchronizerTokenPattern($this->storage, $this->config);
        }

        return $this->synchronizer;
    }

    /**
     * Get or create Double Submit Cookie Pattern instance
     */
    private function getDoubleSubmit(): DoubleSubmitCookiePattern
    {
        if (!$this->doubleSubmit instanceof DoubleSubmitCookiePattern) {
            if ($this->secret === null) {
                throw new RuntimeException(
                    'Secret is required for Double Submit Cookie Pattern. ' .
                    'Use CsrfProtection::doubleSubmit($secret) factory method.'
                );
            }

            $this->doubleSubmit = new DoubleSubmitCookiePattern($this->secret, $this->config);
        }

        return $this->doubleSubmit;
    }
}
