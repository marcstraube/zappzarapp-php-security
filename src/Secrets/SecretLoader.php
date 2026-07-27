<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets;

use Zappzarapp\Security\Secrets\Exception\InvalidSecretNameException;
use Zappzarapp\Security\Secrets\Exception\SecretLoadException;
use Zappzarapp\Security\Secrets\Exception\SecretNotFoundException;

/**
 * Loads secrets from one or more sources with secure defaults
 *
 * Sources are queried in constructor order; the first source that has the
 * secret wins. Secure defaults, by design:
 *
 * - A missing secret throws SecretNotFoundException - there is no silent
 *   `$default` parameter for credentials. Optional secrets require the
 *   explicit tryLoad() opt-in.
 * - A secret that exists but is empty throws SecretLoadException instead
 *   of falling through to the next source, so misconfiguration surfaces
 *   immediately.
 * - Environment variable fallback is opt-in: add an EnvSecretSource
 *   explicitly after the file source.
 *
 * ## Usage
 *
 * ```php
 * // Docker secrets only (recommended)
 * $loader = SecretLoader::docker();
 *
 * // Docker secrets with explicit env fallback
 * $loader = new SecretLoader(new FileSecretSource(), new EnvSecretSource('APP_'));
 *
 * $dbPassword = $loader->load('db_password');
 * $optional   = $loader->tryLoad('sentry_dsn');
 * ```
 */
final readonly class SecretLoader
{
    /**
     * @var list<SecretSourceInterface>
     */
    private array $sources;

    /**
     * At least one source is required by signature - a loader without
     * sources cannot exist.
     */
    public function __construct(
        SecretSourceInterface $source,
        SecretSourceInterface ...$fallbackSources,
    ) {
        $sources = [$source];
        foreach ($fallbackSources as $fallbackSource) {
            $sources[] = $fallbackSource;
        }

        $this->sources = $sources;
    }

    /**
     * Create a loader for Docker secrets (/run/secrets), no fallbacks
     */
    public static function docker(): self
    {
        return new self(new FileSecretSource());
    }

    /**
     * Load a secret, throwing if it cannot be found
     *
     * @throws InvalidSecretNameException If the name fails validation
     * @throws SecretLoadException If a secret exists but is empty or unreadable
     * @throws SecretNotFoundException If no source has the secret
     */
    public function load(SecretName|string $name): SecretValue
    {
        $secretName = is_string($name) ? new SecretName($name) : $name;

        foreach ($this->sources as $source) {
            $raw = $source->fetch($secretName);

            if ($raw === null) {
                continue;
            }

            if ($raw === '') {
                throw SecretLoadException::emptySecret($secretName->value, $source->describe());
            }

            return new SecretValue($raw);
        }

        throw SecretNotFoundException::named($secretName->value, $this->sourceDescriptions());
    }

    /**
     * Load an optional secret, or null if no source has it
     *
     * This is the explicit opt-in for optional secrets. Only "not found"
     * maps to null - invalid names, empty secrets and unreadable files
     * still throw, because those are configuration errors.
     *
     * @throws InvalidSecretNameException If the name fails validation
     * @throws SecretLoadException If a secret exists but is empty or unreadable
     */
    public function tryLoad(SecretName|string $name): ?SecretValue
    {
        try {
            return $this->load($name);
        } catch (SecretNotFoundException) {
            return null;
        }
    }

    /**
     * Descriptions of all configured sources, for error messages
     *
     * @return list<string>
     */
    private function sourceDescriptions(): array
    {
        return array_map(
            static fn(SecretSourceInterface $source): string => $source->describe(),
            $this->sources
        );
    }
}
