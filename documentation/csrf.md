# CSRF Protection

Cross-Site Request Forgery (CSRF) protection using synchronizer tokens and
double-submit cookie patterns.

## Quick Start

```php
use Zappzarapp\Security\Csrf\CsrfProtection;
use Zappzarapp\Security\Csrf\Storage\SessionCsrfStorage;

$csrf = new CsrfProtection(new SessionCsrfStorage());
$token = $csrf->generateToken();

// In your form
echo '<input type="hidden" name="_csrf" value="' . $token->getValue() . '">';

// On submission
if (!$csrf->validateToken($_POST['_csrf'])) {
    throw new \RuntimeException('Invalid CSRF token');
}
```

## Classes

| Class                       | Description                       |
| --------------------------- | --------------------------------- |
| `CsrfProtection`            | Main CSRF protection handler      |
| `SynchronizerTokenPattern`  | Server-side token storage pattern |
| `DoubleSubmitCookiePattern` | Stateless cookie-based pattern    |
| `SessionCsrfStorage`        | Store tokens in PHP session       |
| `ArrayCsrfStorage`          | In-memory storage (for testing)   |
| `CsrfToken`                 | Token value object                |

## Patterns

### Synchronizer Token Pattern

Stores tokens server-side in session storage. Most secure option for traditional
applications.

```php
use Zappzarapp\Security\Csrf\Pattern\SynchronizerTokenPattern;
use Zappzarapp\Security\Csrf\Storage\SessionCsrfStorage;

$pattern = new SynchronizerTokenPattern(new SessionCsrfStorage());

// Generate token for form
$token = $pattern->generate('my-form');

// Validate on submission
if ($pattern->validate('my-form', $_POST['_csrf'])) {
    // Valid token
}
```

### Double Submit Cookie Pattern

Stateless pattern that uses a cookie and form field. Suitable for stateless
APIs.

```php
use Zappzarapp\Security\Csrf\Pattern\DoubleSubmitCookiePattern;

$pattern = new DoubleSubmitCookiePattern($secretKey);

// Generate token
$token = $pattern->generate();

// Set cookie (you must send this to the client)
setcookie('csrf_token', $token->getValue(), [
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Strict'
]);

// Validate (compares cookie value with header/form value)
if ($pattern->validate($_COOKIE['csrf_token'], $_POST['_csrf'])) {
    // Valid
}
```

## Configuration

```php
use Zappzarapp\Security\Csrf\CsrfConfig;

$config = new CsrfConfig(
    tokenLength: 32,           // Token byte length
    tokenLifetime: 3600,       // Token TTL in seconds
    regenerateOnValidation: true  // Generate new token after validation
);
```

## Storage Backends

### Session Storage

```php
use Zappzarapp\Security\Csrf\Storage\SessionCsrfStorage;

// Requires session_start()
$storage = new SessionCsrfStorage();
```

### Custom Storage

Implement `CsrfStorageInterface` for custom backends (Redis, database, etc.).

```php
use Zappzarapp\Security\Csrf\Storage\CsrfStorageInterface;

class RedisCsrfStorage implements CsrfStorageInterface
{
    public function store(string $tokenId, string $token, int $ttl): void
    {
        // Store in Redis
    }

    public function retrieve(string $tokenId): ?string
    {
        // Retrieve from Redis
    }

    public function remove(string $tokenId): void
    {
        // Remove from Redis
    }
}
```

## Integration Examples

### With HTML Forms

```php
// Controller
$token = $csrf->generateToken();

// View
<form method="POST">
    <input type="hidden" name="_csrf" value="<?= htmlspecialchars($token->getValue()) ?>">
    <!-- form fields -->
</form>

// Handler
$csrf->validateToken($_POST['_csrf']);
```

### With AJAX

```php
// Include token in meta tag
<meta name="csrf-token" content="<?= htmlspecialchars($token->getValue()) ?>">

// JavaScript
fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content
    }
});

// Server-side
$token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
$csrf->validateToken($token);
```

## Security Considerations

1. **Use HTTPS** - Tokens can be intercepted over plain HTTP
2. **Set SameSite=Strict** - For double-submit cookies, use strict SameSite
3. **Validate on state changes** - Always validate tokens on POST, PUT, DELETE
4. **Don't expose in URLs** - Tokens in URLs can leak via Referer header
5. **Regenerate periodically** - Use `regenerateOnValidation` or manually
   regenerate
