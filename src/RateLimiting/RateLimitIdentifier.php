<?php

declare(strict_types=1);

namespace Zappzarapp\Security\RateLimiting;

/**
 * Rate limit identifier builder
 *
 * Creates unique identifiers for rate limiting based on various factors such as
 * IP address, user ID, API key, or custom combinations.
 *
 * ## Framework Integration
 *
 * This class intentionally does NOT parse X-Forwarded-For or other proxy headers.
 * Parsing these headers securely requires a trusted proxy list - without it, any
 * client can spoof their IP address by sending a forged X-Forwarded-For header.
 *
 * Always use your framework's request abstraction, which handles trusted proxy
 * configuration properly.
 *
 * @example Symfony integration:
 * ```php
 * // Symfony's Request::getClientIp() respects Request::setTrustedProxies()
 * // Configure trusted proxies in framework.yaml or via Request::setTrustedProxies()
 * $ip = $request->getClientIp();
 * $identifier = RateLimitIdentifier::fromRequest($ip, $user?->getId());
 * ```
 *
 * @example Laravel integration:
 * ```php
 * // Laravel's Request::ip() uses the TrustProxies middleware
 * // Configure trusted proxies in App\Http\Middleware\TrustProxies
 * $ip = $request->ip();
 * $identifier = RateLimitIdentifier::fromRequest($ip);
 * ```
 *
 * @example PSR-7 with trusted proxy middleware:
 * ```php
 * // Use a middleware that validates trusted proxies and sets a reliable attribute
 * $ip = $request->getAttribute('client-ip') ?? $request->getServerParams()['REMOTE_ADDR'];
 * $identifier = RateLimitIdentifier::fromIp($ip);
 * ```
 *
 * @see https://symfony.com/doc/current/deployment/proxies.html Symfony Trusted Proxies
 * @see https://laravel.com/docs/requests#configuring-trusted-proxies Laravel Trusted Proxies
 */
final readonly class RateLimitIdentifier
{
    /**
     * Delimiter between type and value in identifiers
     */
    private const string TYPE_DELIMITER = ':';

    /**
     * Delimiter between composite identifiers
     */
    private const string COMPOSITE_DELIMITER = '|';

    private function __construct(
        private string $value,
    ) {
    }

    /**
     * Escape delimiters in values to prevent collision attacks
     */
    private static function escape(string $value): string
    {
        // Escape backslash first, then delimiters
        return str_replace(
            ['\\', self::TYPE_DELIMITER, self::COMPOSITE_DELIMITER],
            ['\\\\', '\\:', '\\|'],
            $value
        );
    }

    /**
     * Get the identifier value
     */
    public function value(): string
    {
        return $this->value;
    }

    /**
     * Create from IP address
     *
     * Note: IP addresses (including IPv6 with colons) are not escaped because
     * the 'ip:' prefix is fixed and unambiguous.
     */
    public static function fromIp(string $ip): self
    {
        return new self('ip' . self::TYPE_DELIMITER . $ip);
    }

    /**
     * Create from user ID
     */
    public static function fromUserId(int|string $userId): self
    {
        return new self('user' . self::TYPE_DELIMITER . $userId);
    }

    /**
     * Create from API key
     */
    public static function fromApiKey(string $apiKey): self
    {
        // Hash the API key to avoid storing it in plain text (hash output is safe, no escaping needed)
        return new self('api' . self::TYPE_DELIMITER . hash('sha256', $apiKey));
    }

    /**
     * Create from custom value
     *
     * Values are escaped to prevent collision attacks where a malicious value
     * could contain delimiters (: or |) to impersonate other identifiers.
     */
    public static function custom(string $type, string $value): self
    {
        return new self(self::escape($type) . self::TYPE_DELIMITER . self::escape($value));
    }

    /**
     * Create composite identifier from multiple factors
     *
     * Individual identifier values are already properly formatted, so we only
     * join them. The escape() is applied in custom() for user-provided values.
     *
     * @param list<self> $identifiers
     */
    public static function composite(array $identifiers): self
    {
        $values = array_map(
            static fn (self $id): string => $id->value,
            $identifiers
        );

        return new self(implode(self::COMPOSITE_DELIMITER, $values));
    }

    /**
     * Create from request (IP + optional user)
     */
    public static function fromRequest(?string $ip = null, int|string|null $userId = null): self
    {
        if ($ip === null) {
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        }

        if ($userId !== null) {
            return self::composite([
                self::fromIp($ip),
                self::fromUserId($userId),
            ]);
        }

        return self::fromIp($ip);
    }
}
