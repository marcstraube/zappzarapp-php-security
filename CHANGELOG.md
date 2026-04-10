# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1](https://github.com/marcstraube/zappzarapp-php-security/compare/v1.0.0...v1.0.1) (2026-04-10)


### Miscellaneous Chores

* **deps-dev:** Bump league/commonmark from 2.8.0 to 2.8.2 ([#10](https://github.com/marcstraube/zappzarapp-php-security/issues/10)) ([49e6de6](https://github.com/marcstraube/zappzarapp-php-security/commit/49e6de624665f0de86da9c1c1399da26f117e3a0))
* **deps-dev:** Bump the dev-dependencies group across 1 directory with 7 updates ([#11](https://github.com/marcstraube/zappzarapp-php-security/issues/11)) ([4b1cb6d](https://github.com/marcstraube/zappzarapp-php-security/commit/4b1cb6da9277d55186d3fa8df81abe573b59411b))
* **deps:** Bump actions/upload-artifact from 6 to 7 ([#6](https://github.com/marcstraube/zappzarapp-php-security/issues/6)) ([c33a822](https://github.com/marcstraube/zappzarapp-php-security/commit/c33a822dd49d0b4cfb8ea3f444bc4a4d3ffb3059))
* **deps:** Bump codecov/codecov-action from 5 to 6 ([#12](https://github.com/marcstraube/zappzarapp-php-security/issues/12)) ([7afe7b8](https://github.com/marcstraube/zappzarapp-php-security/commit/7afe7b87ffe533cb11de21e1ef2f3c5e589a873a))

## [1.0.0] - 2026-02-12

### Added

#### CSP Module

- `CspDirectives` - Immutable CSP configuration with fluent API
- `HeaderBuilder` - CSP header generation with Report-Only support
- `NonceGenerator` - Cryptographically secure nonce generation (256-bit)
- `NonceRegistry` - Static singleton for simple nonce access
- Security policies: `STRICT`, `LENIENT`, `UNSAFE_EVAL`, `UNSAFE_INLINE`
- WebSocket support with secure defaults (`wss://`, `https://`)
- Violation reporting (`report-uri`, `report-to`)

#### Security Headers Module

- `SecurityHeaders` - Immutable aggregate of all security headers
- `SecurityHeadersBuilder` - Header array generation
- HSTS with preload support
- COOP, COEP, CORP headers
- Permissions-Policy with feature directives
- X-Frame-Options, X-Content-Type-Options, Referrer-Policy

#### CSRF Module

- `CsrfProtection` - Token-based CSRF protection
- Synchronizer Token pattern
- Double Submit Cookie pattern
- Configurable token storage (Session, Cookie)

#### Cookie Module

- `SecureCookie` - Secure cookie handling
- `CookieBuilder` - Fluent cookie construction
- SameSite, HttpOnly, Secure flags
- Optional encryption support

#### Password Module

- `DefaultPasswordHasher` - Argon2id/bcrypt hashing with pepper support
- `PasswordPolicy` - Configurable password validation rules
- `PwnedPasswordChecker` - HIBP breach detection via k-Anonymity API
- Secure memory clearing via `sodium_memzero()`

#### Sanitization Module

- `HtmlSanitizer` - XSS-safe HTML sanitization
- `UriSanitizer` - URI validation with SSRF protection
- `PathValidator` - Directory traversal prevention
- `SqlIdentifierSanitizer` - SQL injection prevention for identifiers
- IDN homograph attack detection

#### Rate Limiting Module

- `DefaultRateLimiter` - Configurable rate limiting
- Token Bucket algorithm
- Sliding Window algorithm
- Storage backends: InMemory, Redis, Memcached

#### SRI Module

- `SriHashGenerator` - Subresource Integrity hash generation
- `IntegrityAttribute` - SRI attribute building
- SSRF protection for remote resources
- Multiple hash algorithm support (SHA-256, SHA-384, SHA-512)

#### Logging Module

- `SecurityAuditLogger` - Security event logging
- `SecurityEvent` - Structured security events
- `SecurityEventType` - Event type enumeration
- Correlation ID support
- PSR-3 compatible

### Security

- Defense-in-Depth: Redundant validation at multiple layers
- Cryptographic randomness only (`random_bytes()`)
- Input validation rejects `;`, `\n`, `\r`, `'` (injection prevention)
- Memory clearing for sensitive data
- Private IP range blocking (SSRF protection)
- Taint analysis enabled (Psalm)

### Quality

- PHPStan Level 8
- Psalm Level 1 with taint analysis
- 100% Mutation Score (Infection)
- Deptrac architecture enforcement (0 violations)
- PHP 8.4+ with strict types
- Immutable value objects throughout

[1.0.0]:
  https://github.com/marcstraube/zappzarapp-php-security/releases/tag/v1.0.0
