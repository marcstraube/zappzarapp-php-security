# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via GitHub's private vulnerability reporting:

1. Go to the
   [Security Advisories page](https://github.com/marcstraube/zappzarapp-php-security/security/advisories/new)
2. Click "Report a vulnerability"
3. Fill in the details

Alternatively, you can email security concerns to: **<security@marcstraube.de>**

### What to include in your report

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Response Timeline

This is currently a solo-maintained project. I will respond as quickly as
possible, typically within a week. Critical vulnerabilities are prioritized.

### Disclosure Policy

- We follow coordinated vulnerability disclosure
- We will credit reporters (unless anonymity is requested)
- Security advisories will be published after fixes are released

## Security Measures

This package implements multiple security layers:

- **Dependency Scanning**: Composer audit + roave/security-advisories
- **Static Analysis**: PHPStan (level 8) + Psalm (level 1)
- **Code Quality**: PHPMD, Rector, PHP-CS-Fixer
- **Automated Updates**: Renovate + Dependabot
- **CI/CD**: GitHub Actions + GitLab CI with security checks
- **Signed Releases**: GPG-signed tags and commits

## Known Security Considerations

### CSP Nonce Generation

- Uses `random_bytes(32)` for cryptographically secure randomness (256 bits)
- Nonces are base64-encoded (44 characters with padding)
- Instance-based design safe for long-running processes (Swoole, RoadRunner)
- Each NonceGenerator instance caches its nonce for consistent use
- Throws `RandomException` if no secure random source available
- Defense-in-Depth: Both `NonceGenerator` and `NonceRegistry` validate nonces
  independently to prevent injection attacks

### Password Security

- **Memory Clearing**: Uses `sodium_memzero()` when available to securely clear
  passwords from memory after hashing/verification
- **k-Anonymity for HIBP**: Only the first 5 characters of the SHA-1 hash are
  sent to the Have I Been Pwned API, protecting the actual password
- **Pepper Support**: Additional secret key stored separately from database
- **Argon2id**: Default algorithm with resistance against GPU-based attacks

### SSRF Protection

- SRI module validates URLs before fetching remote resources
- Blocks private/reserved IP ranges (10.x, 172.16-31.x, 192.168.x, localhost)
- Blocks IPv6 link-local and loopback addresses
- Configurable via `PrivateNetworkValidator`

### Input Validation

All user input is validated with Defense-in-Depth:

- CSP directives reject `;` (directive injection), `\n`/`\r` (header injection)
- Nonces reject single quotes (CSP injection)
- URI sanitizer detects IDN homograph attacks (mixed Cyrillic/Latin)
- Path validator prevents directory traversal (`../`)

### Static Analysis

- **Taint Analysis**: Psalm with `runTaintAnalysis="true"` tracks untrusted
  input through the codebase
- **Banned Functions**: PHPStan blocks dangerous functions (eval, exec, etc.)
- **Strict Types**: All files use `declare(strict_types=1)`

### API Design

**Security by Default:**

- Constructor defaults to `SecurityPolicy::STRICT` (no unsafe-\* directives)
- All sources default to `'self'` only
- Explicit opt-in required for permissive policies

**Type Safety:**

- Readonly value objects prevent modification after creation
- Enum-based security policies prevent invalid states
- Immutable fluent API ensures configuration correctness

**Configuration Independence:**

- Security policy (unsafe-\* directives) is independent of WebSocket
  configuration
- WebSocket can be used in both strict production (real-time features) and
  lenient development (hot reload)
- No implicit environment detection or global state

**Example secure configurations:**

```php
// Production strict CSP with real-time features
new CspDirectives(
    securityPolicy: SecurityPolicy::STRICT,
    websocketHost: 'api.example.com:443'
);

// Legacy framework requiring eval, but still secure inline handling
new CspDirectives(
    securityPolicy: SecurityPolicy::UNSAFE_EVAL
);

// Complete custom control with explicit parameters
new CspDirectives(
    defaultSrc: "'self'",
    scriptSrc: "'self' 'nonce-{NONCE}' https://trusted-cdn.com",
    resources: new ResourceDirectives(
        img: "'self' data: https://cdn.example.com",
        connect: "'self' https://api.example.com"
    ),
    securityPolicy: SecurityPolicy::STRICT
);
```

### Validation

The package performs minimal validation to catch configuration errors:

- **Default-src required**: Throws `InvalidArgumentException` if empty (CSP spec
  requirement)
- **WebSocket format**: Triggers `E_USER_WARNING` for invalid host:port format

Intentionally **no validation** on:

- Security policy choice (user's responsibility)
- Directive combinations (flexibility for edge cases)
- WebSocket + Security Policy combinations (independent concerns)

This approach balances security with flexibility for legitimate use cases.
