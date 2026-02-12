<?php

/** @noinspection PhpMultipleClassDeclarationsInspection Psalm stubs conflict with native PHP 8.2 SensitiveParameter */

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Pattern;

use InvalidArgumentException;
use Random\RandomException;
use SensitiveParameter;
use Zappzarapp\Security\Csrf\CsrfConfig;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Token\CsrfToken;
use Zappzarapp\Security\Csrf\Token\CsrfTokenGenerator;
use Zappzarapp\Security\Csrf\Validation\ValidatesCsrfToken;

/**
 * HMAC-Signed Double Submit Cookie Pattern implementation
 *
 * Enhanced version of the double-submit pattern that uses HMAC signatures
 * to cryptographically bind tokens to a server secret, providing defense-in-depth.
 *
 * ## How it works:
 * 1. Server generates a random token
 * 2. Cookie stores: base64(token)
 * 3. Form/header contains: base64(token).base64(HMAC(token, secret))
 * 4. Validation verifies HMAC signature matches
 *
 * ## Security benefits:
 * - HMAC binding prevents token forgery even if random values are predictable
 * - Server secret adds defense-in-depth layer
 * - SameSite cookie policy provides additional CSRF protection
 *
 * ## Usage:
 * ```php
 * $pattern = new DoubleSubmitCookiePattern(secret: $serverSecret);
 * $token = $pattern->generateToken();
 *
 * // Set cookie with raw token
 * setcookie($pattern->cookieName(), $token->value(), $pattern->cookieOptions());
 *
 * // Include signed token in form
 * echo '<input type="hidden" name="' . $pattern->fieldName() . '" value="' . $pattern->signToken($token) . '">';
 *
 * // Validate on submit
 * $pattern->validate($_COOKIE[$pattern->cookieName()], $_POST[$pattern->fieldName()]);
 * ```
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
 */
final readonly class DoubleSubmitCookiePattern
{
    use ValidatesCsrfToken;

    /**
     * Minimum secret length in bytes
     */
    private const int MIN_SECRET_LENGTH = 32;

    /**
     * HMAC algorithm (SHA-256 provides sufficient security)
     */
    private const string HMAC_ALGORITHM = 'sha256';

    private CsrfTokenGenerator $generator;

    /**
     * @param string $secret Server-side secret for HMAC signing (min 32 bytes)
     * @param CsrfConfig $config CSRF configuration
     *
     * @throws InvalidArgumentException If secret is shorter than 32 bytes
     */
    public function __construct(
        #[SensitiveParameter] private string $secret,
        private CsrfConfig $config = new CsrfConfig(),
    ) {
        if (strlen($secret) < self::MIN_SECRET_LENGTH) {
            throw new InvalidArgumentException(
                sprintf('Secret must be at least %d bytes, got %d', self::MIN_SECRET_LENGTH, strlen($secret))
            );
        }

        $this->generator = new CsrfTokenGenerator();
    }

    /**
     * Generate a new token
     *
     * @throws RandomException If no suitable random source is available
     */
    public function generateToken(): CsrfToken
    {
        return $this->generator->generate();
    }

    /**
     * Sign a token for inclusion in form/header
     *
     * Returns: base64(token).base64(HMAC(token, secret))
     *
     * @param CsrfToken $token The token to sign
     *
     * @return string Signed token string (token.signature)
     */
    public function signToken(CsrfToken $token): string
    {
        $signature = hash_hmac(self::HMAC_ALGORITHM, $token->value(), $this->secret, true);

        return $token->value() . '.' . base64_encode($signature);
    }

    /**
     * Validate that cookie token and signed form/header token match
     *
     * Validates:
     * 1. Cookie token format is valid
     * 2. Signed token can be parsed (token.signature format)
     * 3. Token portion matches cookie token (timing-safe)
     * 4. HMAC signature is valid (timing-safe)
     *
     * @param string $cookieToken Raw token from the cookie
     * @param string $signedToken Signed token from header or body (token.signature)
     *
     * @throws CsrfTokenMismatchException If tokens don't match or signature invalid
     * @throws InvalidCsrfTokenException If token format is invalid
     */
    public function validate(string $cookieToken, string $signedToken): void
    {
        // Validate cookie token format
        $cookie = new CsrfToken($cookieToken);

        // Parse signed token
        $parts = explode('.', $signedToken, 2);
        if (count($parts) !== 2) {
            throw CsrfTokenMismatchException::tokenMismatch();
        }

        [$tokenPart, $signaturePart] = $parts;

        // Validate token part matches cookie (timing-safe)
        if (!hash_equals($cookie->value(), $tokenPart)) {
            throw CsrfTokenMismatchException::tokenMismatch();
        }

        // Verify HMAC signature (timing-safe)
        $expectedSignature = hash_hmac(self::HMAC_ALGORITHM, $tokenPart, $this->secret, true);
        $providedSignature = base64_decode($signaturePart, true);

        if ($providedSignature === false) {
            throw CsrfTokenMismatchException::tokenMismatch();
        }

        if (!hash_equals($expectedSignature, $providedSignature)) {
            throw CsrfTokenMismatchException::tokenMismatch();
        }
    }

    /**
     * Check if tokens are valid
     *
     * @param string $cookieToken Raw token from the cookie
     * @param string $signedToken Signed token from header or body
     */
    public function isValid(string $cookieToken, string $signedToken): bool
    {
        try {
            $this->validate($cookieToken, $signedToken);

            return true;
        } catch (CsrfTokenMismatchException|InvalidCsrfTokenException) {
            return false;
        }
    }

    /**
     * Get cookie options for setting the CSRF cookie
     *
     * @param bool $secure Use Secure flag (set true in production)
     *
     * @return array{name: string, expires: int, path: string, secure: bool, httponly: bool, samesite: string}
     */
    public function cookieOptions(bool $secure = true): array
    {
        return [
            'name'     => $this->config->cookieName,
            'expires'  => $this->config->ttl > 0 ? time() + $this->config->ttl : 0,
            'path'     => '/',
            'secure'   => $secure,
            'httponly' => false, // Must be readable by JavaScript
            'samesite' => 'Strict',
        ];
    }

    /**
     * Get the cookie name from config
     */
    public function cookieName(): string
    {
        return $this->config->cookieName;
    }

    /**
     * Get the header name from config
     */
    public function headerName(): string
    {
        return $this->config->headerName;
    }

    /**
     * Get the field name from config
     */
    public function fieldName(): string
    {
        return $this->config->fieldName;
    }
}
