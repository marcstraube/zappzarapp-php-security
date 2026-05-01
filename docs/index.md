# Zappzarapp PHP Security Library

A comprehensive PHP security library providing protection against common web
vulnerabilities.

## Quick Links

| Module                            | Description                                                                                |
| --------------------------------- | ------------------------------------------------------------------------------------------ |
| [CSP](csp.md)                     | Content Security Policy with nonce-based script execution                                  |
| [Headers](headers.md)             | Security headers (HSTS, COOP, COEP, CORP, Permissions-Policy)                              |
| [CSRF](csrf.md)                   | Cross-Site Request Forgery protection with synchronizer tokens and double-submit cookies   |
| [Cookie](cookie.md)               | Secure cookie handling with encryption, SameSite, and HttpOnly support                     |
| [Password](password.md)           | Secure password hashing with Argon2id/bcrypt, pepper support, and pwned password detection |
| [Sanitization](sanitization.md)   | HTML, URI, and path sanitization to prevent XSS and injection attacks                      |
| [Rate Limiting](rate-limiting.md) | Token bucket and sliding window rate limiting with storage backends                        |
| [SRI](sri.md)                     | Subresource Integrity hash generation and verification with SSRF protection                |
| [Analyzer](analyzer.md)           | Security header analyzer for auditing and CI integration                                   |
| [Middleware](middleware.md)       | PSR-15 middleware for security headers, CSP, CSRF, and rate limiting                       |
| [Logging](logging.md)             | Security audit logging with correlation IDs                                                |
| [Glossary](glossary.md)           | Security terms and concepts explained                                                      |

## Installation

```bash
composer require zappzarapp/security
```

## Requirements

- PHP 8.4+
- ext-sodium (recommended for secure memory clearing)
- ext-intl (recommended for IDN validation)

## Quick Start

```php
use Zappzarapp\Security\Password\Hashing\DefaultPasswordHasher;
use Zappzarapp\Security\Csrf\Synchronizer\SynchronizerTokenManager;
use Zappzarapp\Security\Headers\SecurityHeaders;

// Password hashing
$hasher = DefaultPasswordHasher::argon2id();
$hash = $hasher->hash('MySecurePassword');

// CSRF protection
$csrf = new SynchronizerTokenManager();
$token = $csrf->generate();

// Security headers
$headers = SecurityHeaders::strict();
```

## Security Best Practices

1. **Always use HTTPS** - Security features like HSTS, Secure cookies, and CSP
   are most effective over HTTPS
2. **Keep secrets separate** - Store pepper keys, CSRF secrets, and encryption
   keys outside your codebase
3. **Validate input** - Use sanitizers for user input, but don't rely on them as
   your only defense
4. **Log security events** - Use SecurityAuditLogger to track authentication
   failures, rate limits, and attacks
5. **Set security headers** - Use SecurityHeaders::strict() as a baseline for
   production

## License

MIT License
