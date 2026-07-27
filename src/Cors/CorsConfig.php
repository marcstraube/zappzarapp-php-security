<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Cors;

use InvalidArgumentException;

/**
 * Immutable CORS configuration
 *
 * Controls which cross-origin requests are permitted and which CORS response
 * headers are emitted. Defaults are restrictive: no origins are allowed until
 * explicitly configured.
 *
 * Origins may be matched exactly (e.g. {@code https://example.com}), via the
 * wildcard {@code *} (any origin), or via a single subdomain wildcard pattern
 * (e.g. {@code https://*.example.com}).
 *
 * In a subdomain pattern the {@code *} must always be followed by a dot, i.e.
 * {@code https://*.example.com}. A pattern such as {@code https://*example.com}
 * would also match unrelated hosts like {@code https://evilexample.com}, so the
 * leading dot is what restricts the match to genuine subdomains.
 *
 * Security: per the Fetch standard, the wildcard origin {@code *} is rejected
 * when credentials are allowed, because browsers refuse that combination and
 * silently leaking it would create a false sense of security.
 */
final readonly class CorsConfig
{
    private const string WILDCARD = '*';

    /** @var list<string> */
    public array $allowedOrigins;

    /** @var list<string> */
    public array $allowedMethods;

    /** @var list<string> */
    public array $allowedHeaders;

    /** @var list<string> */
    public array $exposedHeaders;

    /**
     * @param list<string> $allowedOrigins Permitted origins, the wildcard {@code *}, or subdomain patterns
     * @param list<string> $allowedMethods Permitted HTTP methods for actual requests
     * @param list<string> $allowedHeaders Permitted request headers for preflight requests
     * @param list<string> $exposedHeaders Response headers exposed to the client
     * @param bool $allowCredentials Whether credentialed requests are permitted
     * @param int $maxAge Preflight cache lifetime in seconds (0 disables the header)
     *
     * @throws InvalidArgumentException If credentials are combined with the wildcard origin,
     *                                  if {@code maxAge} is negative, or if any value contains
     *                                  a CR or LF character (header injection)
     */
    public function __construct(
        array $allowedOrigins = [],
        array $allowedMethods = ['GET', 'HEAD', 'POST'],
        array $allowedHeaders = [],
        array $exposedHeaders = [],
        public bool $allowCredentials = false,
        public int $maxAge = 0,
    ) {
        if ($maxAge < 0) {
            throw new InvalidArgumentException('Max age must be greater than or equal to 0');
        }

        if ($allowCredentials && in_array(self::WILDCARD, $allowedOrigins, true)) {
            throw new InvalidArgumentException(
                'Wildcard origin "*" cannot be combined with credentials; specify explicit origins',
            );
        }

        $this->assertNoHeaderInjection($allowedOrigins, 'origin');
        $this->assertNoHeaderInjection($allowedMethods, 'method');
        $this->assertNoHeaderInjection($allowedHeaders, 'header');
        $this->assertNoHeaderInjection($exposedHeaders, 'exposed header');

        $this->allowedOrigins = $allowedOrigins;
        $this->allowedMethods = $allowedMethods;
        $this->allowedHeaders = $allowedHeaders;
        $this->exposedHeaders = $exposedHeaders;
    }

    /**
     * @param list<string> $allowedOrigins
     *
     * @throws InvalidArgumentException
     */
    public function withAllowedOrigins(array $allowedOrigins): self
    {
        return new self(
            $allowedOrigins,
            $this->allowedMethods,
            $this->allowedHeaders,
            $this->exposedHeaders,
            $this->allowCredentials,
            $this->maxAge,
        );
    }

    /**
     * @param list<string> $allowedMethods
     *
     * @throws InvalidArgumentException
     */
    public function withAllowedMethods(array $allowedMethods): self
    {
        return new self(
            $this->allowedOrigins,
            $allowedMethods,
            $this->allowedHeaders,
            $this->exposedHeaders,
            $this->allowCredentials,
            $this->maxAge,
        );
    }

    /**
     * @param list<string> $allowedHeaders
     *
     * @throws InvalidArgumentException
     */
    public function withAllowedHeaders(array $allowedHeaders): self
    {
        return new self(
            $this->allowedOrigins,
            $this->allowedMethods,
            $allowedHeaders,
            $this->exposedHeaders,
            $this->allowCredentials,
            $this->maxAge,
        );
    }

    /**
     * @param list<string> $exposedHeaders
     *
     * @throws InvalidArgumentException
     */
    public function withExposedHeaders(array $exposedHeaders): self
    {
        return new self(
            $this->allowedOrigins,
            $this->allowedMethods,
            $this->allowedHeaders,
            $exposedHeaders,
            $this->allowCredentials,
            $this->maxAge,
        );
    }

    /**
     * @throws InvalidArgumentException If credentials are combined with the wildcard origin
     */
    public function withCredentials(bool $allowCredentials = true): self
    {
        return new self(
            $this->allowedOrigins,
            $this->allowedMethods,
            $this->allowedHeaders,
            $this->exposedHeaders,
            $allowCredentials,
            $this->maxAge,
        );
    }

    /**
     * @throws InvalidArgumentException If {@code maxAge} is negative
     */
    public function withMaxAge(int $maxAge): self
    {
        return new self(
            $this->allowedOrigins,
            $this->allowedMethods,
            $this->allowedHeaders,
            $this->exposedHeaders,
            $this->allowCredentials,
            $maxAge,
        );
    }

    /**
     * Create a permissive configuration allowing any origin
     *
     * Credentials remain disabled because they are incompatible with the
     * wildcard origin.
     */
    public static function permissive(): self
    {
        return new self(
            allowedOrigins: [self::WILDCARD],
            allowedMethods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization'],
        );
    }

    /**
     * Create a configuration restricted to the given origins
     *
     * @param list<string> $origins
     *
     * @throws InvalidArgumentException If any origin contains a CR or LF character
     */
    public static function forOrigins(array $origins): self
    {
        return new self(
            allowedOrigins: $origins,
            allowedMethods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization'],
        );
    }

    /**
     * Whether any origin is permitted via the wildcard
     */
    public function allowsAnyOrigin(): bool
    {
        return in_array(self::WILDCARD, $this->allowedOrigins, true);
    }

    /**
     * Whether the given request origin is permitted
     */
    public function isOriginAllowed(string $origin): bool
    {
        if ($this->allowsAnyOrigin()) {
            return true;
        }

        return array_any($this->allowedOrigins, fn (string $allowed): bool => $this->matchesOrigin($allowed, $origin));
    }

    /**
     * Resolve the Access-Control-Allow-Origin value for a request origin
     *
     * Returns {@code *} only when any origin is permitted and credentials are
     * disabled; otherwise the request origin is echoed back. Returns null when
     * the origin is not permitted.
     */
    public function resolveAllowOrigin(string $origin): ?string
    {
        if (!$this->isOriginAllowed($origin)) {
            return null;
        }

        if ($this->allowsAnyOrigin() && !$this->allowCredentials) {
            return self::WILDCARD;
        }

        return $origin;
    }

    private function matchesOrigin(string $pattern, string $origin): bool
    {
        // A pattern without a wildcard yields a fully escaped regex, so an exact
        // match falls out of the same code path as subdomain wildcards.
        $regex = '#^' . str_replace('\*', '[A-Za-z0-9.-]+', preg_quote($pattern, '#')) . '$#';

        return preg_match($regex, $origin) === 1;
    }

    /**
     * @param list<string> $values
     *
     * @throws InvalidArgumentException If any value contains a CR or LF character
     */
    private function assertNoHeaderInjection(array $values, string $label): void
    {
        foreach ($values as $value) {
            if (str_contains($value, "\r") || str_contains($value, "\n")) {
                throw new InvalidArgumentException(
                    sprintf('CORS %s must not contain CR or LF characters', $label),
                );
            }
        }
    }
}
