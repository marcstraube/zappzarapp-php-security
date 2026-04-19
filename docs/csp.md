# Content Security Policy (CSP)

Build secure Content Security Policy headers with nonce-based script execution
and strict defaults.

## Quick Start

```php
use Zappzarapp\Security\Csp\HeaderBuilder;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;

$generator = new NonceGenerator();
$csp = HeaderBuilder::build(CspDirectives::strict(), $generator);
header("Content-Security-Policy: {$csp}");

// Use nonce in HTML
$nonce = $generator->get();
echo "<script nonce=\"{$nonce}\">console.log('Safe!');</script>";
```

## Classes

| Class                  | Description                                  |
| ---------------------- | -------------------------------------------- |
| `HeaderBuilder`        | Builds CSP header strings                    |
| `CspDirectives`        | Immutable CSP configuration value object     |
| `NonceGenerator`       | Instance-based cryptographic nonce generator |
| `NonceRegistry`        | Static singleton for simple usage            |
| `NonceProvider`        | Interface for dependency injection           |
| `SecurityPolicy`       | Enum for security policy levels              |
| `ResourceDirectives`   | Resource fetch directive configuration       |
| `NavigationDirectives` | Navigation directive configuration           |
| `ReportingConfig`      | CSP reporting configuration                  |

## Security Policies

Four security levels via `SecurityPolicy` enum:

| Policy          | unsafe-eval | unsafe-inline | Use Case                          |
| --------------- | ----------- | ------------- | --------------------------------- |
| `STRICT`        | No          | No            | Production (default)              |
| `LENIENT`       | Yes         | Yes           | Development, legacy apps          |
| `UNSAFE_EVAL`   | Yes         | No            | Frameworks requiring eval (Vue 2) |
| `UNSAFE_INLINE` | No          | Yes           | Rare - avoid if possible          |

```php
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\SecurityPolicy;

// Strict (default) - recommended for production
$csp = new CspDirectives();
$csp = new CspDirectives(securityPolicy: SecurityPolicy::STRICT);

// Lenient - for development or legacy
$csp = new CspDirectives(securityPolicy: SecurityPolicy::LENIENT);

// Unsafe eval only - for frameworks like Vue 2
$csp = new CspDirectives(securityPolicy: SecurityPolicy::UNSAFE_EVAL);
```

## Factory Methods

Convenient presets for common scenarios:

```php
// Production: Strict nonce-based CSP
$csp = CspDirectives::strict();

// Development: Lenient with hot reload support
$csp = CspDirectives::development('localhost:5173');

// Legacy: For frameworks requiring eval
$csp = CspDirectives::legacy();
```

## Nonce Generation

### Instance-Based (Recommended)

```php
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;

$generator = new NonceGenerator();
$nonce = $generator->get();  // Same nonce for this instance

// Safe for long-running processes (Swoole, RoadRunner)
// Each instance generates its own 256-bit cryptographic nonce
```

### Static Registry (Simple Apps)

```php
use Zappzarapp\Security\Csp\Nonce\NonceRegistry;

$nonce = NonceRegistry::get();

// Reset for new request (required in long-running processes)
NonceRegistry::reset();
```

### Dependency Injection

```php
use Zappzarapp\Security\Csp\Nonce\NonceProvider;
use Zappzarapp\Security\Csp\Nonce\NullNonce;

// For testing - no nonce in output
$csp = HeaderBuilder::build(new CspDirectives(), new NullNonce());

// Custom provider
class MyNonceProvider implements NonceProvider {
    public function get(): string {
        return $this->frameworkNonce;
    }
}
```

## Directive Configuration

### Resource Directives

```php
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\ResourceDirectives;

// Fluent API
$csp = (new CspDirectives())
    ->withImgSrc("'self' data: https://cdn.example.com")
    ->withFontSrc("'self' https://fonts.gstatic.com")
    ->withConnectSrc("'self' https://api.example.com");

// Or via ResourceDirectives
$resources = new ResourceDirectives(
    img: "'self' https://images.example.com",
    font: "'self' https://fonts.gstatic.com",
    connect: "'self' https://api.example.com",
    media: "'self'",
    worker: "'self' blob:",
    frame: "'self' https://embed.example.com"
);
$csp = (new CspDirectives())->withResources($resources);
```

### Navigation Directives

```php
use Zappzarapp\Security\Csp\Directive\NavigationDirectives;

$navigation = new NavigationDirectives(
    frameAncestors: "'none'",      // Who can embed this page
    baseUri: "'self'",              // Restrict <base> tag
    formAction: "'self'"            // Form submission targets
);
$csp = (new CspDirectives())->withNavigation($navigation);
```

### Script and Style Sources

```php
// Nonce is auto-injected if not present
$csp = (new CspDirectives())
    ->withScriptSrc("'self' https://trusted-cdn.com")
    ->withStyleSrc("'self' https://fonts.googleapis.com");
```

## WebSocket Support

```php
// Production with real-time features
$csp = (new CspDirectives())->withWebSocket('api.example.com:443');

// Development with hot reload
$csp = CspDirectives::development('localhost:5173');
```

**Note:** Use `host:port` format, not full URL.

## Reporting

### Report-Only Mode

Test policies without blocking:

```php
// Report-only header (violations logged, not blocked)
$header = HeaderBuilder::buildReportOnlyHeader(new CspDirectives());
header($header);
```

### Violation Reporting

```php
use Zappzarapp\Security\Csp\Directive\ReportingConfig;

$reporting = new ReportingConfig(
    uri: '/csp-report',           // Legacy report-uri
    endpoint: 'csp-endpoint',     // Modern report-to
    upgradeInsecure: true         // Upgrade HTTP to HTTPS
);

$csp = new CspDirectives(reporting: $reporting);

// Or fluent
$csp = (new CspDirectives())
    ->withReportUri('/csp-report')
    ->withReportTo('csp-endpoint');
```

## Default Directives

| Directive                   | Default Value                         |
| --------------------------- | ------------------------------------- |
| `default-src`               | `'self'`                              |
| `script-src`                | `'self' 'nonce-...' 'strict-dynamic'` |
| `style-src`                 | `'self' 'nonce-...'`                  |
| `img-src`                   | `'self' data:`                        |
| `object-src`                | `'none'`                              |
| `frame-ancestors`           | `'self'`                              |
| `base-uri`                  | `'self'`                              |
| `form-action`               | `'self'`                              |
| `upgrade-insecure-requests` | Enabled                               |

## Complete Example

```php
use Zappzarapp\Security\Csp\HeaderBuilder;
use Zappzarapp\Security\Csp\Directive\CspDirectives;
use Zappzarapp\Security\Csp\Directive\ReportingConfig;
use Zappzarapp\Security\Csp\Nonce\NonceGenerator;

$generator = new NonceGenerator();

$directives = (new CspDirectives(
    reporting: new ReportingConfig(uri: '/csp-violations')
))
    ->withImgSrc("'self' data: https://cdn.example.com")
    ->withFontSrc("'self' https://fonts.gstatic.com")
    ->withConnectSrc("'self' https://api.example.com")
    ->withWebSocket('api.example.com:443');

$csp = HeaderBuilder::build($directives, $generator);
header("Content-Security-Policy: {$csp}");

$nonce = $generator->get();
?>
<!DOCTYPE html>
<html>
<head>
    <script nonce="<?= $nonce ?>">
        console.log('Secure inline script!');
    </script>
    <style nonce="<?= $nonce ?>">
        body { margin: 0; }
    </style>
</head>
<body>...</body>
</html>
```

## Common Pitfalls

### Nonce Must Be Used in HTML

```php
// WRONG: Script blocked
echo "<script>alert('blocked');</script>";

// CORRECT: Script allowed via nonce
echo "<script nonce=\"{$nonce}\">alert('allowed');</script>";
```

### Nonce Changes Per Request

Don't cache HTML containing nonces:

```php
// WRONG: Stale nonce
$html = $cache->get('page', fn() => renderPage());

// CORRECT: Cache data, render fresh
$data = $cache->get('data', fn() => fetchData());
$html = renderPage($data, $generator->get());
```

### strict-dynamic Ignores Allowlists

With `strict-dynamic`, URL allowlists in script-src are ignored:

```php
// URL allowlist ignored by modern browsers with strict-dynamic
->withScriptSrc("'self' https://cdn.example.com")

// Instead, use nonce on script tags
echo "<script nonce=\"{$nonce}\" src=\"https://cdn.example.com/lib.js\"></script>";
```

### Nonce Validation (Defense in Depth)

External nonces are validated to prevent injection:

```php
// These throw InvalidDirectiveValueException:
NonceRegistry::set('');                    // Empty
NonceRegistry::set("valid; malicious");    // Semicolon (CSP injection)
NonceRegistry::set("valid\nX-Header:");    // Newline (header injection)
NonceRegistry::set("valid' 'unsafe");      // Quote (CSP injection)

// Valid:
NonceRegistry::set('abc123XYZ');           // Alphanumeric
NonceRegistry::set('dGVzdC1ub25jZQ==');    // Base64
```

## Security Considerations

1. **Use STRICT policy** - Default to strictest settings, relax only when
   necessary
2. **Always use nonces** - Never rely on `'unsafe-inline'` in production
3. **Test in report-only** - Deploy new policies in report-only mode first
4. **Monitor violations** - Set up CSP reporting endpoints
5. **256-bit nonces** - Generated with `random_bytes(32)` for cryptographic
   security
6. **Reset in async** - Call `NonceRegistry::reset()` in Swoole/RoadRunner
