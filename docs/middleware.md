# PSR-15 Middleware

Drop-in PSR-15 middleware for any compliant framework (Slim, Mezzio, Laravel via
bridge, etc.).

## Installation

The middleware requires PSR-15 and PSR-7 packages:

```bash
composer require psr/http-server-middleware psr/http-server-handler
```

## Security Headers Middleware

Applies all configured security headers to responses.

```php
use Zappzarapp\Security\Headers\SecurityHeaders;
use Zappzarapp\Security\Middleware\SecurityHeadersMiddleware;

$middleware = new SecurityHeadersMiddleware(SecurityHeaders::strict());

// In Slim:
$app->add($middleware);
```

## CSP Middleware

Injects Content-Security-Policy headers with nonce support. The `NonceProvider`
is stored in the request attribute `csp-nonce` for template access.

```php
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Middleware\CspMiddleware;

$middleware = new CspMiddleware(CspDirectives::strict());

// In Slim:
$app->add($middleware);
```

### Accessing the Nonce in Templates

```php
// In a PSR-15 handler or controller:
$nonce = $request->getAttribute('csp-nonce')->get();
echo "<script nonce=\"{$nonce}\">...</script>";
```

### Report-Only Mode

```php
$middleware = new CspMiddleware(
    directives: CspDirectives::strict(),
    reportOnly: true,
);
```

## CSRF Middleware

Validates CSRF tokens on state-changing requests (POST, PUT, DELETE, PATCH).
Safe methods (GET, HEAD, OPTIONS) pass through with the token stored in request
attribute `csrf-token`.

```php
use Zappzarapp\Security\Csrf\CsrfProtection;
use Zappzarapp\Security\Csrf\Storage\SessionCsrfStorage;
use Zappzarapp\Security\Middleware\CsrfMiddleware;

$protection = CsrfProtection::synchronizer(new SessionCsrfStorage());
$middleware = new CsrfMiddleware($protection);

// In Slim:
$app->add($middleware);
```

### Token Source Priority

1. Request header (configured via `CsrfConfig::headerName`, default:
   `X-CSRF-Token`)
2. Parsed body field (configured via `CsrfConfig::fieldName`, default:
   `_csrf_token`)

### Using the Token in Forms

```php
// In a PSR-15 handler:
$token = $request->getAttribute('csrf-token');
echo "<input type=\"hidden\" name=\"_csrf_token\" value=\"{$token}\">";
```

## Double Submit CSRF Middleware

Stateless CSRF protection for SPA/API setups that cannot rely on server-side
session storage. Uses the HMAC-signed Double Submit Cookie pattern: every
response carries a JavaScript-readable cookie holding the raw token, while the
matching signed token is exposed via request attribute `csrf-token`. On
state-changing requests the cookie token is validated against the signed token
from the header or body.

```php
use Zappzarapp\Security\Csrf\CsrfProtection;
use Zappzarapp\Security\Middleware\DoubleSubmitCsrfMiddleware;

$protection = CsrfProtection::doubleSubmit($secret); // secret: min 32 bytes
$middleware = new DoubleSubmitCsrfMiddleware($protection);

// In Slim:
$app->add($middleware);
```

### Token Source Priority

1. Request header (configured via `CsrfConfig::headerName`, default:
   `X-CSRF-Token`)
2. Parsed body field (configured via `CsrfConfig::fieldName`, default:
   `_csrf_token`)

### Using the Signed Token in a SPA

```php
// In a PSR-15 handler — hand the signed token to JavaScript:
$signedToken = $request->getAttribute('csrf-token');
echo "<meta name=\"csrf-token\" content=\"{$signedToken}\">";
// JS reads the cookie + meta token and sends the signed value in X-CSRF-Token.
```

### Development Over HTTP

The cookie sets the `Secure` flag by default. Disable it for local HTTP testing:

```php
$middleware = new DoubleSubmitCsrfMiddleware($protection, secure: false);
```

## Rate Limit Middleware

Enforces rate limits and returns 429 responses when exceeded. Rate limit headers
(`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`) are applied
to all responses.

```php
use Zappzarapp\Security\Middleware\RateLimitMiddleware;
use Zappzarapp\Security\RateLimiting\DefaultRateLimiter;

$limiter    = DefaultRateLimiter::api();
$middleware = new RateLimitMiddleware($limiter, $responseFactory);

// In Slim:
$app->add($middleware);
```

### Custom Identifier

By default, the middleware identifies clients by IP address. Override with a
custom extractor:

```php
$middleware = new RateLimitMiddleware(
    limiter: $limiter,
    responseFactory: $responseFactory,
    identifierExtractor: fn ($request) => RateLimitIdentifier::fromUserId(
        $request->getAttribute('user_id'),
    ),
);
```

## CORS Middleware

Applies Cross-Origin Resource Sharing headers and answers preflight (`OPTIONS`)
requests with a `204`. Requests without an `Origin` header pass through
untouched; requests from a disallowed origin receive no CORS headers, leaving
the browser to block the response. A PSR-17 response factory is required to
build preflight responses.

```php
use Zappzarapp\Security\Cors\CorsConfig;
use Zappzarapp\Security\Middleware\CorsMiddleware;

$config     = CorsConfig::forOrigins(['https://app.example.com']);
$middleware = new CorsMiddleware($config, $responseFactory); // PSR-17 factory

// In Slim:
$app->add($middleware);
```

### Configuration

`CorsConfig` is immutable; every `with*()` method returns a new instance.
Defaults are restrictive — no origins are allowed until configured.

```php
$config = new CorsConfig(
    allowedOrigins: ['https://app.example.com', 'https://*.example.com'],
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['X-Total-Count'],
    allowCredentials: true,
    maxAge: 3600,
);
```

### Origin Matching

| Form              | Example                 | Matches                                    |
| ----------------- | ----------------------- | ------------------------------------------ |
| Exact             | `https://example.com`   | only that exact origin                     |
| Wildcard          | `*`                     | any origin (credentials must be disabled)  |
| Subdomain pattern | `https://*.example.com` | any subdomain — the `*` must precede a dot |

### Presets

```php
CorsConfig::permissive();                          // any origin, no credentials
CorsConfig::forOrigins(['https://app.example.com']); // restrict to given origins
```

### Security Notes

- Combining the wildcard origin `*` with `allowCredentials: true` throws an
  `InvalidArgumentException` — browsers reject that combination.
- `Vary: Origin` is emitted for specific origins so shared caches never serve
  one origin's CORS headers to another.
- CR/LF characters in any configured value are rejected (header injection).

## Combining Middleware

Apply middleware in the correct order (outermost runs first):

```php
// CORS first — answers preflight OPTIONS cheaply, before any other check
$app->add(new CorsMiddleware($corsConfig, $responseFactory));

// Rate limiting next (cheap check)
$app->add(new RateLimitMiddleware($limiter, $responseFactory));

// Then CSRF (blocks invalid state-changing requests)
$app->add(new CsrfMiddleware($protection));

// Then security headers (applied to all responses)
$app->add(new SecurityHeadersMiddleware(SecurityHeaders::strict()));

// Then CSP (adds nonce to request for handlers)
$app->add(new CspMiddleware(CspDirectives::strict()));
```
