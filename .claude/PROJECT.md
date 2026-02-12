# Project Configuration

Project-specific settings for Claude agents. Agents reference this file for
namespace, structure, and tooling details.

## Package

| Field       | Value                                 |
| ----------- | ------------------------------------- |
| Name        | `zappzarapp/security`                 |
| Description | Security library for PHP applications |
| PHP Version | `^8.4`                                |
| License     | MIT                                   |

## Namespace

```text
Zappzarapp\Security\
```

## Directory Structure

```text
src/
├── Csp/            # Content Security Policy
├── Headers/        # Security Headers (HSTS, COOP, COEP, etc.)
├── Csrf/           # CSRF Protection
├── Cookie/         # Secure Cookie Handling
├── Password/       # Password Hashing & Validation
├── Sanitization/   # Input Sanitization (HTML, URI, Path, SQL)
├── RateLimiting/   # Rate Limiting (Token Bucket, Sliding Window)
├── Sri/            # Subresource Integrity
└── Logging/        # Security Audit Logging

tests/
└── [mirrors src/ structure]
```

## Modules

| Module       | Namespace                           | Description                          |
| ------------ | ----------------------------------- | ------------------------------------ |
| Csp          | `Zappzarapp\Security\Csp\`          | CSP header building with nonces      |
| Headers      | `Zappzarapp\Security\Headers\`      | HSTS, COOP, COEP, Permissions-Policy |
| Csrf         | `Zappzarapp\Security\Csrf\`         | Token-based CSRF protection          |
| Cookie       | `Zappzarapp\Security\Cookie\`       | Secure cookie handling               |
| Password     | `Zappzarapp\Security\Password\`     | Hashing, policy, HIBP checking       |
| Sanitization | `Zappzarapp\Security\Sanitization\` | HTML, URI, Path, SQL sanitization    |
| RateLimiting | `Zappzarapp\Security\RateLimiting\` | Token Bucket, Sliding Window         |
| Sri          | `Zappzarapp\Security\Sri\`          | SRI hash generation                  |
| Logging      | `Zappzarapp\Security\Logging\`      | Security event audit logging         |

## Configuration Files

| Tool         | Config File              | Purpose                   |
| ------------ | ------------------------ | ------------------------- |
| PHPStan      | `phpstan.neon`           | Static analysis (Level 8) |
| Psalm        | `psalm.xml`              | Type checking (Level 1)   |
| PHPMD        | `phpmd.xml`              | Mess detection            |
| PHP-CS-Fixer | `.php-cs-fixer.dist.php` | Code style (PER-CS)       |
| PHPUnit      | `phpunit.xml.dist`       | Testing                   |
| Infection    | `infection.json5`        | Mutation testing          |
| Deptrac      | `deptrac.yaml`           | Architecture layers       |
| Rector       | `rector.php`             | Code modernization        |
| Composer     | `composer.json`          | Dependencies              |

## Make Targets

### Primary Commands

| Command           | Purpose                                   |
| ----------------- | ----------------------------------------- |
| `make check`      | Run all checks (without mutation testing) |
| `make check-full` | Run all checks (with mutation testing)    |
| `make test`       | Run PHPUnit tests                         |

### Individual Tools

| Command           | Tool                      |
| ----------------- | ------------------------- |
| `make cs-fix`     | PHP-CS-Fixer (auto-fix)   |
| `make cs-check`   | PHP-CS-Fixer (check only) |
| `make analyse`    | PHPStan                   |
| `make psalm`      | Psalm                     |
| `make phpmd`      | PHPMD                     |
| `make rector`     | Rector (apply)            |
| `make rector-dry` | Rector (preview)          |
| `make deptrac`    | Deptrac                   |
| `make infection`  | Infection                 |
| `make security`   | Composer audit            |
| `make docs`       | PHPDocumentor             |
| `make hooks`      | Install git hooks         |
| `make md-fix`     | Prettier (format MD)      |
| `make md-check`   | Prettier (check only)     |
| `make md-lint`    | Markdownlint              |

## Quality Targets

| Metric               | Target |
| -------------------- | ------ |
| PHPStan Level        | 8      |
| Psalm Level          | 1      |
| Code Coverage        | >95%   |
| Mutation Score (MSI) | 100%   |
| Deptrac Violations   | 0      |

> **Note:** 100% coverage is not achievable due to:
>
> - Network I/O code (`@codeCoverageIgnore`)
> - Session tests running in separate processes (PHPUnit limitation)
> - Fallback code for missing extensions (sodium_memzero)

## Key Entry Points

| Module       | Primary Class            | Purpose                        |
| ------------ | ------------------------ | ------------------------------ |
| Csp          | `HeaderBuilder`          | Build CSP headers              |
| Headers      | `SecurityHeadersBuilder` | Build all security headers     |
| Csrf         | `CsrfProtection`         | Token generation & validation  |
| Cookie       | `CookieBuilder`          | Secure cookie construction     |
| Password     | `DefaultPasswordHasher`  | Argon2id hashing with pepper   |
| Password     | `PasswordPolicy`         | Policy-based validation        |
| Password     | `PwnedPasswordChecker`   | HIBP breach detection          |
| Sanitization | `HtmlSanitizer`          | XSS-safe HTML sanitization     |
| Sanitization | `UriSanitizer`           | URI validation, SSRF blocking  |
| Sanitization | `PathValidator`          | Directory traversal prevention |
| RateLimiting | `DefaultRateLimiter`     | Rate limiting with storage     |
| Sri          | `SriHashGenerator`       | SRI hash generation            |
| Logging      | `SecurityAuditLogger`    | Security event logging         |

## Architecture

Read `deptrac.yaml` for authoritative layer configuration.

Each module follows a layered architecture:

- **Top Layer**: Public API (Builder, Protection, Validator)
- **Middle Layers**: Implementation (Algorithm, Storage, Pattern)
- **Foundation**: Value Objects, Enums, Exceptions

## Security Considerations

### Banned Functions

Configured in `phpstan.neon`:

```text
eval, exec, passthru, shell_exec, system, proc_open,
debug_backtrace, dd, dump, phpinfo, print_r, var_dump
```

### Secure Defaults

| Setting                   | Default | Reason                    |
| ------------------------- | ------- | ------------------------- |
| SecurityPolicy            | STRICT  | No unsafe-\* by default   |
| default-src               | 'self'  | Restrictive default       |
| object-src                | 'none'  | Prevents plugin-based XSS |
| upgrade-insecure-requests | true    | Forces HTTPS              |

### Input Validation

All external input must reject:

- Semicolons (`;`) - directive injection
- Newlines (`\n`, `\r`) - header injection
- Single quotes in nonces (`'`) - delimiter escape

## Commit Conventions

### Format

```text
<type>(<scope>): <description>

[optional body]

[optional footer]
Co-Authored-By: Claude <noreply@anthropic.com>
```

### Types

| Type       | Description                      |
| ---------- | -------------------------------- |
| `feat`     | New feature                      |
| `fix`      | Bug fix                          |
| `docs`     | Documentation                    |
| `style`    | Code style (no logic change)     |
| `refactor` | Refactoring (no behavior change) |
| `test`     | Tests                            |
| `chore`    | Maintenance                      |
| `security` | Security fix                     |

### Scopes

`csp`, `headers`, `csrf`, `cookie`, `password`, `sanitization`, `rate-limiting`,
`sri`, `logging`

## CI/CD

### GitHub Actions

- CodeQL security scan
- All quality checks
- Coverage upload to Codecov
- SBOM generation

### Required for Merge

- All checks pass
- GPG-signed commits
- Linear history
