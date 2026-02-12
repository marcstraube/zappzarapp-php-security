# Subresource Integrity (SRI)

Generate and verify integrity hashes for external resources to ensure they
haven't been tampered with.

## Quick Start

```php
use Zappzarapp\Security\Sri\IntegrityAttribute;
use Zappzarapp\Security\Sri\HashAlgorithm;

// Generate integrity hash from content
$content = file_get_contents('https://cdn.example.com/script.js');
$integrity = IntegrityAttribute::fromContent($content, HashAlgorithm::SHA384);

echo '<script src="https://cdn.example.com/script.js" integrity="' . $integrity . '"></script>';
```

## Classes

| Class                | Description                                        |
| -------------------- | -------------------------------------------------- |
| `IntegrityAttribute` | SRI integrity attribute value object               |
| `ResourceFetcher`    | Fetches remote resources for hashing               |
| `HashAlgorithm`      | Supported hash algorithms (SHA256, SHA384, SHA512) |

## Generating Hashes

### From Content

```php
use Zappzarapp\Security\Sri\IntegrityAttribute;
use Zappzarapp\Security\Sri\HashAlgorithm;

$content = file_get_contents('/path/to/script.js');
$integrity = IntegrityAttribute::fromContent($content);
// Default: SHA384

// Or specify algorithm
$integrity = IntegrityAttribute::fromContent($content, HashAlgorithm::SHA512);
```

### From Remote URL

```php
use Zappzarapp\Security\Sri\ResourceFetcher;

$fetcher = new ResourceFetcher();
$integrity = $fetcher->fetchAndHash('https://cdn.example.com/script.js');

echo $integrity; // sha384-<base64-encoded-hash>
```

### Configuration

```php
use Zappzarapp\Security\Sri\ResourceFetcher;
use Zappzarapp\Security\Sri\ResourceFetcherConfig;

$config = new ResourceFetcherConfig(
    timeout: 10,
    maxSize: 5 * 1024 * 1024,  // 5MB
    followRedirects: true,
    maxRedirects: 3,
    userAgent: 'SRI-Fetcher/1.0'
);

$fetcher = new ResourceFetcher($config);
```

## Hash Algorithms

| Algorithm | Security             | Performance |
| --------- | -------------------- | ----------- |
| SHA256    | Good                 | Fastest     |
| SHA384    | Better (recommended) | Medium      |
| SHA512    | Best                 | Slowest     |

SHA384 is recommended as the default - it provides strong security with good
browser support.

## HTML Usage

### Scripts

```php
$script = sprintf(
    '<script src="%s" integrity="%s" crossorigin="anonymous"></script>',
    htmlspecialchars($url),
    htmlspecialchars($integrity)
);
```

### Stylesheets

```php
$link = sprintf(
    '<link rel="stylesheet" href="%s" integrity="%s" crossorigin="anonymous">',
    htmlspecialchars($url),
    htmlspecialchars($integrity)
);
```

## Verification

Verify content against an existing integrity hash:

```php
use Zappzarapp\Security\Sri\IntegrityAttribute;

$integrity = IntegrityAttribute::fromString('sha384-oqVuAfXR...');
$content = file_get_contents($url);

if ($integrity->verify($content)) {
    // Content is authentic
}
```

## Build Integration

Generate SRI hashes during your build process:

```php
// build-sri.php
$assets = [
    'https://cdn.example.com/bootstrap.min.css',
    'https://cdn.example.com/jquery.min.js',
];

$fetcher = new ResourceFetcher();
$hashes = [];

foreach ($assets as $url) {
    $hashes[$url] = (string) $fetcher->fetchAndHash($url);
}

file_put_contents('sri-hashes.json', json_encode($hashes, JSON_PRETTY_PRINT));
```

## Security Considerations

1. **Use HTTPS** - SRI doesn't help if the page itself can be modified
2. **Include crossorigin attribute** - Required for CORS-enabled resources
3. **Regenerate on updates** - Hash changes when resource changes
4. **Multiple algorithms** - You can include multiple hashes for fallback
5. **Cache hashes** - Generate at build time, not runtime
6. **Monitor failures** - SRI failures might indicate CDN compromise
