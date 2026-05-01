# ⚡ zappzarapp/security

[![Latest Version](https://img.shields.io/packagist/v/zappzarapp/security.svg)](https://packagist.org/packages/zappzarapp/security)
[![PHP Version](https://img.shields.io/packagist/php-v/zappzarapp/security.svg)](https://packagist.org/packages/zappzarapp/security)
[![License](https://img.shields.io/packagist/l/zappzarapp/security.svg)](https://packagist.org/packages/zappzarapp/security)
[![CI](https://github.com/marcstraube/zappzarapp-php-security/actions/workflows/ci.yml/badge.svg)](https://github.com/marcstraube/zappzarapp-php-security/actions/workflows/ci.yml)

Comprehensive PHP security library providing CSP, Security Headers, CSRF
protection, Secure Cookies, Password Validation, Input Sanitization, Rate
Limiting, SRI, and Audit Logging.

## Highlights

- **All-in-one** — 11 security modules in a single, composable package
- **Secure by default** — strict CSP, no `unsafe-*`, HTTPS-first
- **Framework-agnostic** — works with any PHP 8.4+ application
- **Immutable & type-safe** — readonly classes, enums, `with*()` API
- **Quality-backed** — PHPStan Level 8, Psalm Level 1, 100% Mutation Score,
  Deptrac architecture enforcement
- **PSR-compatible** — PSR-3 (Logging), PSR-15 (Middleware), PSR-18 (HTTP Client)

## Modules

| Module           | Description                                       | Key Classes                                                        |
| ---------------- | ------------------------------------------------- | ------------------------------------------------------------------ |
| **CSP**          | Content Security Policy header building           | `CspDirectives`, `HeaderBuilder`, `NonceGenerator`                 |
| **Headers**      | Security headers (HSTS, Permissions-Policy, etc.) | `SecurityHeaders`, `SecurityHeadersBuilder`                        |
| **CSRF**         | Cross-Site Request Forgery protection             | `CsrfProtection`, `CsrfConfig`                                     |
| **Cookie**       | Secure cookie handling                            | `SecureCookie`, `CookieBuilder`, `CookieOptions`                   |
| **Password**     | Password validation and hashing                   | `PasswordPolicy`, `PwnedPasswordChecker`, `PepperedPasswordHasher` |
| **Sanitization** | Input sanitization (HTML, SQL, URI, Path)         | `HtmlSanitizer`, `UriSanitizer`, `PathValidator`                   |
| **RateLimiting** | Rate limiting with multiple algorithms            | `DefaultRateLimiter`, `RateLimitConfig`                            |
| **SRI**          | Subresource Integrity hash generation             | `SriHashGenerator`, `IntegrityAttribute`                           |
| **Analyzer**     | Security header analysis and auditing             | `SecurityHeaderAnalyzer`, `AnalysisResult`                         |
| **Middleware**   | PSR-15 middleware for drop-in framework integration | `SecurityHeadersMiddleware`, `CsrfMiddleware`, `RateLimitMiddleware` |
| **Logging**      | Security event audit logging                      | `SecurityAuditLogger`, `SecurityEvent`                             |

## Requirements

- PHP ^8.4
- `ext-dom`
- `ext-libxml`
- `ext-sodium`

## Installation

```bash
composer require zappzarapp/security
```

## Quick Start

### Security Headers

```php
use Zappzarapp\Security\Headers\Builder\SecurityHeadersBuilder;

$headers = SecurityHeadersBuilder::recommended()->build();
foreach ($headers as $name => $value) {
    header("{$name}: {$value}");
}
```

### CSP with Nonces

```php
use Zappzarapp\Security\Csp\HeaderBuilder;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;

$generator = new NonceGenerator();
$csp = HeaderBuilder::build(CspDirectives::strict(), $generator);
header("Content-Security-Policy: {$csp}");

$nonce = $generator->get();
echo "<script nonce=\"{$nonce}\">console.log('Safe!');</script>";
```

### CSRF Protection

```php
use Zappzarapp\Security\Csrf\CsrfProtection;
use Zappzarapp\Security\Csrf\Storage\SessionCsrfStorage;

$csrf = new CsrfProtection(new SessionCsrfStorage());

// Generate token for form
$token = $csrf->generateToken();
echo '<input type="hidden" name="_token" value="' . $token->value() . '">';

// Validate on submission
if (!$csrf->validateToken($_POST['_token'])) {
    throw new Exception('CSRF validation failed');
}
```

### Input Sanitization

```php
use Zappzarapp\Security\Sanitization\Html\HtmlSanitizer;
use Zappzarapp\Security\Sanitization\Path\PathValidator;

// Sanitize HTML (removes dangerous tags/attributes)
$sanitizer = new HtmlSanitizer();
$safe = $sanitizer->sanitize($userInput);

// Validate file paths (prevent directory traversal)
$validator = new PathValidator('/var/www/uploads');
if (!$validator->isValid($userPath)) {
    throw new Exception('Invalid path');
}
```

See the [documentation](docs/) for detailed examples of all modules.

## Documentation

Each module has detailed API documentation with class references, configuration
options, and code examples:

| Module                                    | Description                         |
| ----------------------------------------- | ----------------------------------- |
| [CSP](docs/csp.md)                        | Content Security Policy with nonces |
| [Headers](docs/headers.md)                | HSTS, COOP, COEP, CORP, Permissions |
| [CSRF](docs/csrf.md)                      | Token patterns and validation       |
| [Cookie](docs/cookie.md)                  | Secure cookie handling              |
| [Password](docs/password.md)              | Hashing, policies, breach detection |
| [Sanitization](docs/sanitization.md)      | HTML, URI, path sanitization        |
| [Rate Limiting](docs/rate-limiting.md)    | Token bucket, sliding window        |
| [SRI](docs/sri.md)                        | Subresource integrity hashes        |
| [Analyzer](docs/analyzer.md)             | Security header auditing            |
| [Middleware](docs/middleware.md)          | PSR-15 middleware                   |
| [Logging](docs/logging.md)               | Security audit logging              |
| [Glossary](docs/glossary.md)             | Security terminology reference      |

## Versioning

This library follows [Semantic Versioning 2.0.0](https://semver.org/).

All classes, interfaces, and methods in the `Zappzarapp\Security` namespace are
considered public API unless marked with `@internal`. Breaking changes only
happen in major versions, with deprecation warnings at least one minor version
before removal.

Releases are automated via
[release-please](https://github.com/googleapis/release-please) and GPG-signed.
See [CHANGELOG.md](CHANGELOG.md) for release history.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security
considerations.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution
guidelines.

## License

MIT License - see [LICENSE](LICENSE) file for details.
