<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Csrf\Pattern;

use Random\RandomException;
use Zappzarapp\Security\Csrf\CsrfConfig;
use Zappzarapp\Security\Csrf\Exception\CsrfTokenMismatchException;
use Zappzarapp\Security\Csrf\Exception\InvalidCsrfTokenException;
use Zappzarapp\Security\Csrf\Storage\CsrfStorageInterface;
use Zappzarapp\Security\Csrf\Token\CsrfToken;
use Zappzarapp\Security\Csrf\Token\CsrfTokenGenerator;
use Zappzarapp\Security\Csrf\Validation\CsrfValidator;

/**
 * Synchronizer Token Pattern implementation
 *
 * Stores a token in the session and requires it in form submissions.
 * Most common CSRF protection pattern for traditional web applications.
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
 */
final readonly class SynchronizerTokenPattern
{
    private CsrfTokenGenerator $generator;

    private CsrfValidator $validator;

    public function __construct(
        CsrfStorageInterface $storage,
        private CsrfConfig $config = new CsrfConfig(),
    ) {
        $this->generator = new CsrfTokenGenerator();
        $this->validator = new CsrfValidator($storage);
    }

    /**
     * Get the current token (generates and stores if needed)
     *
     * @throws RandomException If no suitable random source is available
     */
    public function getToken(): CsrfToken
    {
        // Check for existing token
        $stored = $this->validator->getStoredToken();
        if ($stored !== null) {
            return new CsrfToken($stored);
        }

        // Generate and store new token
        $token = $this->generator->generate();
        $this->validator->storeToken($token, $this->config->ttl);

        return $token;
    }

    /**
     * Generate a hidden form field with the token
     *
     * @throws RandomException If no suitable random source is available
     */
    public function field(): string
    {
        $token = $this->getToken();

        return sprintf(
            '<input type="hidden" name="%s" value="%s">',
            htmlspecialchars($this->config->fieldName, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
            htmlspecialchars($token->value(), ENT_QUOTES | ENT_HTML5, 'UTF-8')
        );
    }

    /**
     * Validate a token from the request
     *
     * @param string $submittedToken The token from $_POST or headers
     *
     * @throws CsrfTokenMismatchException If validation fails
     * @throws InvalidCsrfTokenException If token format is invalid
     * @throws RandomException If rotation is enabled and random source unavailable
     */
    public function validate(string $submittedToken): void
    {
        $consume = $this->config->singleUse;
        $this->validator->validate($submittedToken, $consume);

        // Rotate token after successful validation if configured
        if ($this->config->rotateOnValidation) {
            $this->regenerate();
        }
    }

    /**
     * Check if a token is valid
     *
     * @param string $submittedToken The token from the request
     */
    public function isValid(string $submittedToken): bool
    {
        return $this->validator->isValid($submittedToken);
    }

    /**
     * Regenerate the token
     *
     * Call after successful login to prevent session fixation.
     *
     * @throws RandomException If no suitable random source is available
     */
    public function regenerate(): CsrfToken
    {
        $this->validator->clearToken();
        $token = $this->generator->generate();
        $this->validator->storeToken($token, $this->config->ttl);

        return $token;
    }

    /**
     * Clear the current token
     */
    public function clear(): void
    {
        $this->validator->clearToken();
    }

    /**
     * Get the field name from config
     */
    public function fieldName(): string
    {
        return $this->config->fieldName;
    }

    /**
     * Get the header name from config
     */
    public function headerName(): string
    {
        return $this->config->headerName;
    }
}
