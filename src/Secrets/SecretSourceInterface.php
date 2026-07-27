<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets;

use Zappzarapp\Security\Secrets\Exception\SecretLoadException;

/**
 * Source that can look up raw secret material by name
 *
 * Implementations return null when the secret does not exist in this source,
 * allowing the loader to fall through to the next source. A secret that
 * exists but cannot be read throws instead of returning null, so
 * misconfiguration surfaces immediately. An existing but empty secret is
 * returned as an empty string - the loader rejects it.
 */
interface SecretSourceInterface
{
    /**
     * Fetch the raw secret value, or null if this source does not have it
     *
     * @throws SecretLoadException If the secret exists but cannot be read
     */
    public function fetch(SecretName $name): ?string;

    /**
     * Describe this source for error messages (e.g. "file:/run/secrets")
     */
    public function describe(): string;
}
