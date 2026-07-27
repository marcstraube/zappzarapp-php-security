<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets\Exception;

use RuntimeException;

/**
 * Exception thrown when a secret cannot be found in any configured source
 *
 * A missing secret throws by default - there are no silent fallback values
 * for credentials. Use SecretLoader::tryLoad() for explicit opt-in to
 * optional secrets.
 */
final class SecretNotFoundException extends RuntimeException
{
    /**
     * Create for a secret not found in any source
     *
     * @param string $name The validated secret name
     * @param list<string> $searchedSources Descriptions of the searched sources
     */
    public static function named(string $name, array $searchedSources): self
    {
        return new self(sprintf(
            'Secret "%s" not found (searched: %s)',
            $name,
            implode(', ', $searchedSources)
        ));
    }
}
