# Security Headers

Configure HTTP security headers to protect against clickjacking, XSS, MIME
sniffing, and more.

## Quick Start

```php
use Zappzarapp\Security\Headers\SecurityHeaders;
use Zappzarapp\Security\Headers\SecurityHeadersSender;

$headers = SecurityHeaders::strict();
$sender = new SecurityHeadersSender($headers);
$sender->send();
```

## Classes

| Class                   | Description                                   |
| ----------------------- | --------------------------------------------- |
| `SecurityHeaders`       | Aggregates all security header configurations |
| `SecurityHeadersSender` | Sends headers to the browser                  |
| `HstsConfig`            | HSTS configuration                            |
| `PermissionsPolicy`     | Feature permissions configuration             |

## Preset Configurations

### Strict (Production)

```php
$headers = SecurityHeaders::strict();
// HSTS: 2 years, includeSubDomains
// COOP: same-origin
// COEP: require-corp
// CORP: same-origin
// Referrer-Policy: strict-origin-when-cross-origin
// X-Frame-Options: DENY
// X-Content-Type-Options: nosniff
// X-XSS-Protection: 0
```

### Moderate

```php
$headers = SecurityHeaders::moderate();
// Less restrictive COOP/COEP for better compatibility
```

### Development

```php
$headers = SecurityHeaders::development();
// Minimal headers for local development
```

## Individual Headers

### HSTS (HTTP Strict Transport Security)

Forces HTTPS connections for your domain.

```php
use Zappzarapp\Security\Headers\Hsts\HstsConfig;

$headers = (new SecurityHeaders())
    ->withHsts(HstsConfig::strict());  // 2 years, includeSubDomains

// Custom configuration
$hsts = new HstsConfig(
    maxAge: 31536000,          // 1 year
    includeSubDomains: true,
    preload: true              // Add to browser preload list
);
```

### Content Security Policy

```php
use Zappzarapp\Security\Csp\Directive\CspDirectives;

$csp = CspDirectives::strict()
    ->withScriptSrc(["'self'", 'https://cdn.example.com'])
    ->withStyleSrc(["'self'", "'unsafe-inline'"]);

$headers = (new SecurityHeaders())->withCsp($csp);
```

### Cross-Origin Headers

```php
use Zappzarapp\Security\Headers\Coop\CoopValue;
use Zappzarapp\Security\Headers\Coep\CoepValue;
use Zappzarapp\Security\Headers\Corp\CorpValue;

$headers = (new SecurityHeaders())
    ->withCoop(CoopValue::SAME_ORIGIN)           // Isolate browsing context
    ->withCoep(CoepValue::REQUIRE_CORP)          // Require CORP for all resources
    ->withCorp(CorpValue::SAME_ORIGIN);          // Only serve to same origin
```

### Referrer Policy

```php
use Zappzarapp\Security\Headers\ReferrerPolicy\ReferrerPolicyValue;

$headers = (new SecurityHeaders())
    ->withReferrerPolicy(ReferrerPolicyValue::STRICT_ORIGIN_WHEN_CROSS_ORIGIN);
```

| Value                             | Description                                        |
| --------------------------------- | -------------------------------------------------- |
| `NO_REFERRER`                     | Never send referrer                                |
| `STRICT_ORIGIN_WHEN_CROSS_ORIGIN` | Origin only for cross-origin, full for same-origin |
| `SAME_ORIGIN`                     | Only for same-origin requests                      |
| `NO_REFERRER_WHEN_DOWNGRADE`      | No referrer to HTTP from HTTPS                     |

### X-Frame-Options

```php
use Zappzarapp\Security\Headers\XFrameOptions\XFrameOptionsValue;

$headers = (new SecurityHeaders())
    ->withXFrameOptions(XFrameOptionsValue::DENY);  // No framing allowed
    // Or: SAMEORIGIN - allow same-origin framing
```

### Permissions Policy

Control browser features.

```php
use Zappzarapp\Security\Headers\PermissionsPolicy\PermissionsPolicy;

$policy = PermissionsPolicy::strict();  // Block most features

// Or custom
$policy = (new PermissionsPolicy())
    ->withGeolocation(['self'])
    ->withCamera([])      // Block camera
    ->withMicrophone([]); // Block microphone
```

## Removing Headers

```php
$headers = SecurityHeaders::strict()
    ->withoutHsts()           // Remove HSTS
    ->withoutCoop()           // Remove COOP
    ->withoutXFrameOptions(); // Remove X-Frame-Options
```

## Sending Headers

```php
use Zappzarapp\Security\Headers\SecurityHeadersSender;

$sender = new SecurityHeadersSender($headers);
$sender->send();  // Sends all configured headers

// Or get headers as array
$headerArray = $sender->toArray();
// ['Strict-Transport-Security' => 'max-age=...', ...]
```

## Header Reference

| Header                         | Purpose                      |
| ------------------------------ | ---------------------------- |
| `Strict-Transport-Security`    | Force HTTPS                  |
| `Content-Security-Policy`      | Control resource loading     |
| `Cross-Origin-Opener-Policy`   | Isolate browsing context     |
| `Cross-Origin-Embedder-Policy` | Require CORP for resources   |
| `Cross-Origin-Resource-Policy` | Control resource sharing     |
| `Referrer-Policy`              | Control referrer information |
| `X-Frame-Options`              | Prevent clickjacking         |
| `X-Content-Type-Options`       | Prevent MIME sniffing        |
| `X-XSS-Protection`             | Disable legacy XSS filter    |
| `Permissions-Policy`           | Control browser features     |

## Security Considerations

1. **Start strict, relax as needed** - Begin with `SecurityHeaders::strict()`
   and remove restrictions only when necessary
2. **Test in report-only mode** - CSP supports report-only for testing
3. **Monitor header reports** - Set up CSP/COOP reporting endpoints
4. **HSTS preload** - Consider adding your domain to browser preload lists
5. **X-XSS-Protection: 0** - The legacy XSS filter can be exploited; disable it
   and use CSP instead
