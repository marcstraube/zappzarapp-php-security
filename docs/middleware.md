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
Safe methods (GET, HEAD, OPTIONS) pass through with the token stored in
request attribute `csrf-token`.

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

1. Request header (configured via `CsrfConfig::headerName`, default: `X-CSRF-Token`)
2. Parsed body field (configured via `CsrfConfig::fieldName`, default: `_csrf_token`)

### Using the Token in Forms

```php
// In a PSR-15 handler:
$token = $request->getAttribute('csrf-token');
echo "<input type=\"hidden\" name=\"_csrf_token\" value=\"{$token}\">";
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

## Combining Middleware

Apply middleware in the correct order (outermost runs first):

```php
// Rate limiting first (cheapest check)
$app->add(new RateLimitMiddleware($limiter, $responseFactory));

// Then CSRF (blocks invalid state-changing requests)
$app->add(new CsrfMiddleware($protection));

// Then security headers (applied to all responses)
$app->add(new SecurityHeadersMiddleware(SecurityHeaders::strict()));

// Then CSP (adds nonce to request for handlers)
$app->add(new CspMiddleware(CspDirectives::strict()));
```
