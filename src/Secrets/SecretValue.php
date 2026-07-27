<?php

declare(strict_types=1);

namespace Zappzarapp\Security\Secrets;

use JsonSerializable;
use LogicException;
use SensitiveParameter;
use Zappzarapp\Security\Password\Security\ClearsMemory;
use Zappzarapp\Security\Secrets\Exception\InvalidSecretValueException;

/**
 * Leak-resistant wrapper around a secret value
 *
 * Prevents accidental exposure of the wrapped secret through common channels:
 *
 * - Stack traces: the constructor parameter is marked #[SensitiveParameter]
 * - var_dump() / debuggers: __debugInfo() returns a redacted placeholder
 * - json_encode(): jsonSerialize() returns a redacted placeholder
 * - serialize(): throws to prevent the secret from reaching storage
 * - String casts: not Stringable by design, (string) casts fail
 * - Memory: the internal buffer is zeroed via sodium_memzero() on destruction
 *
 * The only intentional access path is reveal(). Callers own the returned
 * copy and should minimize its lifetime.
 *
 * Note: var_export() and print_r() cannot be intercepted by PHP and would
 * expose the value - both are banned functions in this library (phpstan.neon).
 *
 * ## Usage
 *
 * ```php
 * $secret = new SecretValue($rawValue);
 * $pdo = new PDO($dsn, $user, $secret->reveal());
 * unset($secret); // buffer zeroed
 * ```
 */
final class SecretValue implements JsonSerializable
{
    use ClearsMemory;

    /**
     * Replacement shown instead of the secret in debug and JSON output
     */
    private const string REDACTED = '***REDACTED***';

    /**
     * Null only after the buffer has been zeroed by clearMemory()
     */
    private ?string $value;

    /**
     * @throws InvalidSecretValueException If the value is empty
     */
    public function __construct(
        #[SensitiveParameter]
        string $value,
    ) {
        if ($value === '') {
            throw InvalidSecretValueException::emptyValue();
        }

        $this->value = $value;
    }

    /**
     * Reveal the wrapped secret value
     *
     * Returns a copy the caller is responsible for. The copy is not cleared
     * when this object is destructed - minimize its lifetime.
     *
     * @throws LogicException If the value has already been cleared
     */
    public function reveal(): string
    {
        if ($this->value === null) {
            throw new LogicException('SecretValue has already been cleared');
        }

        return $this->value;
    }

    /**
     * Compare with another secret value in constant time
     *
     * @throws LogicException If either value has already been cleared
     */
    public function equals(self $other): bool
    {
        return hash_equals($this->reveal(), $other->reveal());
    }

    /**
     * Redact the secret in var_dump() and debugger output
     *
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['value' => self::REDACTED];
    }

    /**
     * Redact the secret in json_encode() output
     */
    public function jsonSerialize(): string
    {
        return self::REDACTED;
    }

    /**
     * Prevent the secret from leaking into serialized payloads
     *
     * @return never
     */
    public function __serialize(): array
    {
        throw new LogicException('SecretValue must not be serialized');
    }

    /**
     * Prevent restoring a secret from serialized payloads
     *
     * @param array<array-key, mixed> $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('SecretValue must not be unserialized');
    }

    /**
     * Zero the internal buffer on destruction
     *
     * sodium_memzero() separates shared strings first, so copies handed out
     * via reveal() remain intact while the internal buffer is cleared.
     */
    public function __destruct()
    {
        if ($this->value === null) {
            // Already cleared by an earlier destructor call
            return;
        }

        $this->clearMemory($this->value);
        $this->value = null;
    }
}
