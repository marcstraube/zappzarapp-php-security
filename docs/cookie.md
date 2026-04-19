# Secure Cookies

Secure cookie handling with proper security attributes and optional encryption.

## Quick Start

```php
use Zappzarapp\Security\Cookie\SecureCookie;
use Zappzarapp\Security\Cookie\CookieOptions;

$options = CookieOptions::strict();
$cookie = new SecureCookie('session_id', 'abc123', $options);

// Send to browser
$cookie->send();
```

## Classes

| Class           | Description                                  |
| --------------- | -------------------------------------------- |
| `SecureCookie`  | Secure cookie with proper attributes         |
| `CookieOptions` | Configuration for cookie security attributes |

## Cookie Options

### Strict (Recommended for Sessions)

```php
use Zappzarapp\Security\Cookie\CookieOptions;

$options = CookieOptions::strict();
// HttpOnly: true
// Secure: true
// SameSite: Strict
// Path: /
```

### Lax (For Navigation Cookies)

```php
$options = CookieOptions::lax();
// SameSite: Lax - allows top-level navigation
```

### Custom Configuration

```php
$options = new CookieOptions(
    httpOnly: true,      // Not accessible via JavaScript
    secure: true,        // HTTPS only
    sameSite: 'Strict',  // No cross-site requests
    path: '/',           // Available site-wide
    domain: '.example.com',  // Available to subdomains
    expires: time() + 3600   // 1 hour
);
```

## SameSite Explained

| Value    | Description                                                                |
| -------- | -------------------------------------------------------------------------- |
| `Strict` | Cookie never sent cross-site. Best for auth cookies.                       |
| `Lax`    | Sent on top-level navigation (clicking links). Default in modern browsers. |
| `None`   | Always sent (requires Secure). Use only when necessary for cross-site.     |

## Usage Examples

### Session Cookie

```php
$options = CookieOptions::strict()
    ->withExpires(0);  // Session cookie (expires when browser closes)

$cookie = new SecureCookie('PHPSESSID', session_id(), $options);
$cookie->send();
```

### Remember Me Cookie

```php
$options = CookieOptions::strict()
    ->withExpires(time() + 86400 * 30);  // 30 days

$cookie = new SecureCookie('remember_me', $token, $options);
$cookie->send();
```

### Delete Cookie

```php
$cookie = new SecureCookie('session_id', '', CookieOptions::strict())
    ->delete();  // Sets expiry in the past
```

## Security Considerations

1. **Always use HttpOnly** - Prevents XSS from stealing session cookies
2. **Always use Secure** - Prevents interception over HTTP
3. **Prefer SameSite=Strict** - Strongest CSRF protection
4. **Avoid SameSite=None** - Only if truly needed for cross-site functionality
5. **Short expiry for sensitive cookies** - Session cookies should expire with
   the browser session
6. **Limit Path scope** - Use specific paths when cookie is only needed for
   certain routes
