# Input Sanitization

Sanitize user input to prevent XSS, injection attacks, and other
vulnerabilities.

## Quick Start

```php
use Zappzarapp\Security\Sanitization\Html\HtmlSanitizer;
use Zappzarapp\Security\Sanitization\Html\HtmlSanitizerConfig;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizer;

// HTML sanitization
$htmlSanitizer = new HtmlSanitizer(HtmlSanitizerConfig::standard());
$safe = $htmlSanitizer->sanitize($userHtml);

// URI sanitization
$uriSanitizer = new UriSanitizer(UriSanitizerConfig::web());
$safeUrl = $uriSanitizer->sanitize($userUrl);
```

## Classes

| Class           | Description                                            |
| --------------- | ------------------------------------------------------ |
| `HtmlSanitizer` | Sanitizes HTML, removing dangerous elements/attributes |
| `UriSanitizer`  | Validates and sanitizes URIs                           |
| `PathSanitizer` | Prevents path traversal attacks                        |

## HTML Sanitization

### Preset Configurations

```php
use Zappzarapp\Security\Sanitization\Html\HtmlSanitizer;
use Zappzarapp\Security\Sanitization\Html\HtmlSanitizerConfig;

// Standard - allows common formatting elements
$sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::standard());

// Strip all HTML - escape everything
$sanitizer = new HtmlSanitizer(HtmlSanitizerConfig::stripAll());
```

### Custom Configuration

```php
use Zappzarapp\Security\Sanitization\Html\AllowedElements;
use Zappzarapp\Security\Sanitization\Html\AllowedAttributes;

$config = new HtmlSanitizerConfig(
    elements: AllowedElements::rich(),      // p, a, img, lists, tables, etc.
    attributes: AllowedAttributes::standard()  // href, src, alt, title, etc.
);

$sanitizer = new HtmlSanitizer($config);
```

### Element Presets

| Preset       | Includes                                |
| ------------ | --------------------------------------- |
| `basic()`    | p, br, strong, em, ul, ol, li           |
| `standard()` | basic + h1-h6, blockquote, pre, code    |
| `rich()`     | standard + a, img, table elements, form |

### Security Features

- Removes `<script>`, `<style>`, event handlers (`onclick`, etc.)
- Sanitizes URL attributes (`href`, `src`, `action`)
- Blocks `javascript:`, `data:`, `vbscript:` URLs
- Auto-adds `rel="noopener noreferrer"` to external links
- Preserves content of removed elements (unwraps tags)

```php
$input = '<a href="javascript:alert(1)">Click</a>';
$output = $sanitizer->sanitize($input);
// Output: <a>Click</a> (href removed)

$input = '<p onclick="evil()">Hello</p>';
$output = $sanitizer->sanitize($input);
// Output: <p>Hello</p> (onclick removed)
```

## URI Sanitization

### Validation

```php
use Zappzarapp\Security\Sanitization\Uri\UriSanitizer;
use Zappzarapp\Security\Sanitization\Uri\UriSanitizerConfig;
use Zappzarapp\Security\Sanitization\Exception\UnsafeUriException;

$sanitizer = new UriSanitizer(UriSanitizerConfig::web());

try {
    $sanitizer->validate($url);
} catch (UnsafeUriException $e) {
    // URL is unsafe
}

// Or check without exception
if ($sanitizer->isSafe($url)) {
    // Safe to use
}

// Sanitize - returns empty string if unsafe
$safeUrl = $sanitizer->sanitize($url);
```

### Configuration

```php
$config = new UriSanitizerConfig(
    allowedSchemes: ['https', 'http'],
    blockedSchemes: ['javascript', 'vbscript', 'data'],
    allowRelative: true,
    blockedHosts: ['evil.com'],
    allowedHosts: ['trusted.com'],      // null = allow all
    blockMixedScriptIdn: true           // Block homograph attacks
);
```

### Security Features

- Blocks dangerous schemes (`javascript:`, `vbscript:`, `data:`)
- Normalizes encoding to detect obfuscation attempts
- Detects IDN homograph attacks (mixed scripts like Cyrillic + Latin)
- Host allow/block lists
- Case-insensitive scheme handling

## Path Sanitization

Prevent path traversal attacks (`../`).

```php
use Zappzarapp\Security\Sanitization\Path\PathSanitizer;

$sanitizer = new PathSanitizer('/var/www/uploads');

// Validates path stays within base directory
$safePath = $sanitizer->sanitize('../../etc/passwd');
// Throws exception or returns sanitized path
```

## Security Considerations

1. **Sanitize on output, validate on input** - Sanitization is your last line of
   defense
2. **Context matters** - HTML sanitization is different from SQL escaping
3. **Allowlist, don't blocklist** - Allow known-good elements/schemes
4. **Don't trust sanitizers alone** - Use CSP headers as defense in depth
5. **Test with payloads** - Use OWASP XSS filter evasion cheat sheet
6. **Log blocked content** - Track attack attempts for monitoring
