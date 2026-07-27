# Secrets

Docker/file-based secret loading with secure defaults and a leak-resistant
`SecretValue` wrapper.

Applications running in containers read credentials from Docker secrets
(`/run/secrets/<name>`). This module provides a security-focused standard for
that pattern: a missing secret throws instead of silently falling back to a
default, and loaded secrets are wrapped so they do not leak through stack
traces, logs, `var_dump()`, or `json_encode()`.

## Quick Start

```php
use Zappzarapp\Security\Secrets\SecretLoader;

// Docker secrets only (recommended)
$loader = SecretLoader::docker();

$dbPassword = $loader->load('db_password'); // /run/secrets/db_password
$pdo = new PDO($dsn, $user, $dbPassword->reveal());

// Optional secret: explicit opt-in, returns null when missing
$sentryDsn = $loader->tryLoad('sentry_dsn');
```

With an explicit environment variable fallback:

```php
use Zappzarapp\Security\Secrets\EnvSecretSource;
use Zappzarapp\Security\Secrets\FileSecretSource;
use Zappzarapp\Security\Secrets\SecretLoader;

$loader = new SecretLoader(
    new FileSecretSource(),        // /run/secrets/db_password
    new EnvSecretSource('APP_'),   // falls back to APP_DB_PASSWORD
);
```

## Classes

| Class                   | Description                                             |
| ----------------------- | ------------------------------------------------------- |
| `SecretLoader`          | Loads secrets from ordered sources, throws when missing |
| `SecretValue`           | Leak-resistant wrapper around a loaded secret           |
| `SecretName`            | Validated secret name (value object)                    |
| `FileSecretSource`      | Reads `<basePath>/<name>` and `<basePath>/<name>.txt`   |
| `EnvSecretSource`       | Reads environment variables (explicit opt-in fallback)  |
| `SecretSourceInterface` | Contract for custom secret sources                      |

## Exceptions

| Exception                     | Thrown when                                        |
| ----------------------------- | -------------------------------------------------- |
| `SecretNotFoundException`     | No configured source has the secret                |
| `SecretLoadException`         | A secret exists but is empty or unreadable         |
| `InvalidSecretNameException`  | A secret name fails validation                     |
| `InvalidSecretValueException` | A `SecretValue` is constructed with an empty value |
| `InvalidEnvPrefixException`   | An environment variable prefix fails validation    |

## Secure Defaults

- **Missing secrets throw.** There is no `$default` parameter for credentials -
  a typo in a secret name fails loudly instead of shipping an empty password to
  production. Optional secrets require the explicit `tryLoad()` opt-in, and only
  "not found" maps to `null`.
- **Empty secrets throw.** An existing but empty secret file or environment
  variable is a configuration error and does not fall through to the next
  source.
- **Environment fallback is opt-in.** `SecretLoader::docker()` reads files only;
  add an `EnvSecretSource` explicitly if you need the fallback.
- **Strict name validation.** Secret names allow only `A-Z a-z 0-9 . _ -`, must
  start with an alphanumeric character, and are limited to 255 characters. Path
  separators, control characters, and leading dots are rejected, preventing path
  traversal.
- **Only the trailing newline is trimmed.** Secret files conventionally end with
  a newline (`echo "s3cret" > db_password`); exactly one trailing `\n` or `\r\n`
  is removed. All other whitespace is part of the secret.

## SecretValue

`SecretValue` guards the wrapped secret against common leak channels:

| Channel                  | Behavior                                               |
| ------------------------ | ------------------------------------------------------ |
| Stack traces             | Constructor parameter is `#[SensitiveParameter]`       |
| `var_dump()` / debuggers | `__debugInfo()` returns `***REDACTED***`               |
| `json_encode()`          | Serializes as `"***REDACTED***"`                       |
| `serialize()`            | Throws `LogicException`                                |
| `(string)` cast          | Fails - the class is intentionally not `Stringable`    |
| Memory                   | Buffer is zeroed via `sodium_memzero()` on destruction |

The only intentional access path is `reveal()`:

```php
$secret = $loader->load('db_password');

$pdo = new PDO($dsn, $user, $secret->reveal());
unset($secret); // internal buffer zeroed
```

`reveal()` returns a copy the caller owns - minimize its lifetime. Use
`equals()` for constant-time comparison of two secrets:

```php
if ($providedToken->equals($expectedToken)) {
    // authenticated
}
```

**Limitations:** `var_export()` and `print_r()` bypass `__debugInfo()` and would
expose the value. Both are banned functions in this library's own codebase;
avoid them in application code that handles secrets.

## Environment Variable Mapping

`EnvSecretSource` converts secret names to the conventional environment variable
form: uppercase, with dots and hyphens replaced by underscores, plus an optional
prefix.

| Secret name   | Prefix | Environment variable |
| ------------- | ------ | -------------------- |
| `db_password` | -      | `DB_PASSWORD`        |
| `app.db.pass` | -      | `APP_DB_PASS`        |
| `api-key`     | `APP_` | `APP_API_KEY`        |

Environment variables are visible to the whole process, child processes, and
`/proc` - prefer file-based secrets and use this source only as a deliberate
fallback for environments without them.

## Custom Sources

Implement `SecretSourceInterface` to integrate other backends:

```php
use Zappzarapp\Security\Secrets\SecretName;
use Zappzarapp\Security\Secrets\SecretSourceInterface;

final readonly class VaultSecretSource implements SecretSourceInterface
{
    public function fetch(SecretName $name): ?string
    {
        // return the raw secret, or null if this source does not have it
    }

    public function describe(): string
    {
        return 'vault:https://vault.internal';
    }
}
```

Return `null` for "not found" so the loader can fall through; throw
`SecretLoadException` when a secret exists but cannot be read.

## Logging Integration

The [Logging](logging.md) module's `SecurityAuditLogger` automatically redacts
context keys containing `secret`, `password`, `credential`, and similar terms. A
`SecretValue` passed into a JSON-formatted log serializes as `***REDACTED***`,
adding a second layer of defense:

```php
$auditLogger->warning('Rotation due', ['secret_name' => 'db_password']);
// context value redacted by key convention
```

## Best Practices

1. **Prefer Docker secrets over environment variables** - files mounted at
   `/run/secrets` are scoped to the service and never show up in
   `docker inspect` or `/proc/<pid>/environ`.
2. **Load secrets once at bootstrap** - construct the loader in your
   container/bootstrap code and pass `SecretValue` objects, not raw strings,
   through your configuration.
3. **Minimize `reveal()` lifetime** - reveal at the last possible moment (e.g.
   directly in the `PDO` constructor call) and `unset()` the wrapper when done.
4. **Do not catch `SecretNotFoundException` broadly** - a missing credential is
   a deployment error; let it fail the boot.
