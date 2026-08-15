<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Totp\Exception;

use InvalidArgumentException;

/**
 * Exception thrown when provisioning URI components fail validation
 */
final class InvalidProvisioningDataException extends InvalidArgumentException
{
    /**
     * Create for an empty issuer or account name
     */
    public static function empty(string $field): self
    {
        return new self(sprintf('Provisioning %s must not be empty', $field));
    }

    /**
     * Create for a component containing control characters
     */
    public static function controlCharacters(string $field): self
    {
        return new self(sprintf('Provisioning %s must not contain control characters', $field));
    }

    /**
     * Create for a component containing the label delimiter
     */
    public static function containsColon(string $field): self
    {
        return new self(sprintf(
            'Provisioning %s must not contain a colon (label delimiter)',
            $field
        ));
    }
}
