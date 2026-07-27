# Session

Session security hardening: strict PHP session configuration, session fixation
protection, client fingerprinting, and idle/absolute timeouts.

The module deliberately does not wrap the PHP session lifecycle -
`session_start()`, `session_regenerate_id()` and `session_destroy()` stay in
your hands. It hardens the configuration before start and validates security
metadata stored inside the session on every request.

## Quick Start

```php
use Zappzarapp\Security\Session\SessionConfig;
use Zappzarapp\Security\Session\SessionConfigurator;
use Zappzarapp\Security\Session\SessionContext;
use Zappzarapp\Security\Session\SessionGuard;

$config = new SessionConfig();
$guard  = new SessionGuard($config);

// Bootstrap: harden configuration, then start the session
(new SessionConfigurator())->configure($config);
session_start();

// Every request: validate
$context = SessionContext::fromGlobals();
$result  = $guard->validate($_SESSION, $context);

if (!$result->isValid()) {
    session_unset();
    session_destroy();
    // redirect to login; log $result->description()
}
```

On login (or any privilege change), prevent session fixation:

```php
session_regenerate_id(true);          // new ID, old one deleted
$guard->initialize($_SESSION, $context); // re-bind fingerprint, reset clocks
```

## Classes

| Class                     | Description                                        |
| ------------------------- | -------------------------------------------------- |
| `SessionConfig`           | Immutable configuration with secure defaults       |
| `SessionConfigurator`     | Applies hardened INI/cookie settings before start  |
| `SessionGuard`            | Validates fingerprint and timeouts on each request |
| `SessionContext`          | Client attributes (IP, User-Agent) for binding     |
| `SessionFingerprint`      | Computes the client fingerprint per configuration  |
| `SessionValidationResult` | Validation outcome enum with `isValid()`           |

## Secure Defaults

| Setting          | Default          | Reason                                     |
| ---------------- | ---------------- | ------------------------------------------ |
| Cookie name      | `__Host-session` | Browser-enforced Secure, Path=/, host-only |
| Secure cookie    | on               | Session ID never travels over plain HTTP   |
| HttpOnly         | always on        | Not readable from JavaScript               |
| SameSite         | `Lax`            | Not sent on cross-site subrequests         |
| strict_mode      | always on        | Rejects attacker-supplied session IDs      |
| User-Agent bind  | on               | Stolen ID replayed from other client fails |
| IP bind          | off              | Mobile/NAT users switch IPs legitimately   |
| Idle timeout     | 30 minutes       | Limits exposure of abandoned sessions      |
| Absolute timeout | 12 hours         | Caps total session lifetime                |

`SessionConfig::strict()` tightens this further: IP binding on, SameSite=Strict,
15 minutes idle, 4 hours absolute.

The `__Host-` cookie prefix requires HTTPS. For plain-HTTP development, override
explicitly - this is the deliberate opt-out:

```php
$config = new SessionConfig(secureCookie: false, cookieName: 'dev_session');
```

## Validation Results

`SessionGuard::validate()` returns a `SessionValidationResult`:

| Case                        | Meaning                                      |
| --------------------------- | -------------------------------------------- |
| `VALID`                     | All checks passed; idle timer was refreshed  |
| `UNINITIALIZED`             | `initialize()` was never called              |
| `FINGERPRINT_MISMATCH`      | Client fingerprint changed (possible hijack) |
| `ABSOLUTE_TIMEOUT_EXCEEDED` | Session older than the absolute lifetime     |
| `IDLE_TIMEOUT_EXCEEDED`     | No activity within the idle timeout          |

Treat every non-valid result the same way: destroy the session and require
re-authentication. `description()` provides a log-friendly message - combine it
with the [Logging](logging.md) module:

```php
$auditLogger->warning('Session rejected', ['reason' => $result->value]);
```

## Fingerprinting

The fingerprint is a SHA-256 hash over the bound client attributes, stored
server-side in the session and compared in constant time on each request.

- **User-Agent binding (default on):** a stolen session ID replayed from a
  different browser or tool is rejected. Costs nothing for legitimate users -
  the User-Agent of a browser session is stable.
- **IP binding (opt-in):** stronger, but breaks sessions for users on mobile
  networks, corporate proxies or ISPs with rotating addresses. Enable via
  `new SessionConfig(bindIpAddress: true)` or `SessionConfig::strict()` when
  your user base has stable addresses.

Behind a reverse proxy, `SessionContext::fromGlobals()` sees the proxy's
address. Resolve the client IP from your trusted-proxy configuration and
construct the context explicitly:

```php
$context = new SessionContext($resolvedClientIp, $_SERVER['HTTP_USER_AGENT'] ?? '');
```

## Timeouts

- **Idle timeout** - measured against the last successful `validate()` call;
  each valid request refreshes it. Also drives `session.gc_maxlifetime`.
- **Absolute timeout** - measured against `initialize()`. Re-initialization on
  login resets it, so it caps the authenticated session lifetime regardless of
  activity.

For deterministic time in tests (or app-wide clock control), `SessionGuard`
accepts any PSR-20 clock:

```php
$guard = new SessionGuard($config, $clock); // Psr\Clock\ClockInterface
```

## Best Practices

1. **Configure before start, always** - `SessionConfigurator` throws if the
   session is already active; call it in bootstrap code.
2. **Regenerate on every privilege change** - login, logout, role elevation,
   password change. Follow with `initialize()` to re-bind the fingerprint.
3. **Destroy on any validation failure** - do not "retry" a session that failed
   fingerprint or timeout checks.
4. **Log rejections** - fingerprint mismatches in particular are a signal worth
   monitoring; they may indicate session hijacking attempts.
