<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Headers\PermissionsPolicy;

use Zappzarapp\Security\Headers\Exception\InvalidHeaderValueException;
use Zappzarapp\Security\Headers\Validation\ValidatesHeaderValues;

/**
 * Immutable permission directive with allowlist
 *
 * Represents a single permission directive like "camera=(self)" or "geolocation=()".
 */
final readonly class PermissionDirective
{
    use ValidatesHeaderValues;

    /**
     * @param PermissionFeature $feature The permission feature
     * @param list<string> $allowlist List of allowed origins (empty = blocked, ['*'] = all)
     *
     * @throws InvalidHeaderValueException If allowlist contains invalid values
     */
    public function __construct(
        public PermissionFeature $feature,
        private array $allowlist = [],
    ) {
        foreach ($this->allowlist as $origin) {
            $this->validateAllowlistEntry($origin);
        }
    }

    /**
     * Create directive that blocks this feature entirely
     */
    public static function blocked(PermissionFeature $feature): self
    {
        return new self($feature, []);
    }

    /**
     * Create directive that allows this feature for self only
     */
    public static function self(PermissionFeature $feature): self
    {
        return new self($feature, ['self']);
    }

    /**
     * Create directive that allows this feature for all origins
     */
    public static function all(PermissionFeature $feature): self
    {
        return new self($feature, ['*']);
    }

    /**
     * Create directive with specific origins
     *
     * @param list<string> $origins List of origin URLs
     *
     * @throws InvalidHeaderValueException If origins contain invalid values
     */
    public static function origins(PermissionFeature $feature, array $origins): self
    {
        return new self($feature, $origins);
    }

    /**
     * Add an origin to the allowlist
     *
     * @throws InvalidHeaderValueException If origin is invalid
     */
    public function withOrigin(string $origin): self
    {
        $newAllowlist   = $this->allowlist;
        $newAllowlist[] = $origin;

        return new self($this->feature, $newAllowlist);
    }

    /**
     * Build the directive string
     */
    public function build(): string
    {
        $name = $this->feature->directiveName();

        if ($this->allowlist === []) {
            return $name . '=()';
        }

        $values = [];
        foreach ($this->allowlist as $entry) {
            $values[] = $entry === 'self' || $entry === '*' ? $entry : '"' . $entry . '"';
        }

        return $name . '=(' . implode(' ', $values) . ')';
    }

    /**
     * Get the allowlist
     *
     * @return list<string>
     */
    public function allowlist(): array
    {
        return $this->allowlist;
    }

    /**
     * Check if this feature is blocked
     */
    public function isBlocked(): bool
    {
        return $this->allowlist === [];
    }

    /**
     * Check if this feature allows all origins
     */
    public function allowsAll(): bool
    {
        return in_array('*', $this->allowlist, true);
    }

    /**
     * Validate an allowlist entry
     *
     * @throws InvalidHeaderValueException If entry is invalid
     */
    private function validateAllowlistEntry(string $entry): void
    {
        $this->validateHeaderValue('Permissions-Policy', $entry);

        // Reserved keywords
        if ($entry === 'self' || $entry === '*') {
            return;
        }

        // Must be a valid origin (scheme://host or scheme://host:port)
        if (!$this->isValidOrigin($entry)) {
            throw InvalidHeaderValueException::invalidOrigin($entry);
        }
    }

    /**
     * Check if string is a valid origin
     */
    private function isValidOrigin(string $origin): bool
    {
        // Basic origin validation: must have scheme and host
        $parsed = parse_url($origin);

        if ($parsed === false) {
            return false;
        }

        // Must have scheme and host
        if (!isset($parsed['scheme'], $parsed['host'])) {
            return false;
        }

        // Must not have path (except /) or query
        if (isset($parsed['path']) && $parsed['path'] !== '/') {
            return false;
        }

        return !isset($parsed['query']) && !isset($parsed['fragment']);
    }
}
