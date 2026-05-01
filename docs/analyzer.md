# Security Header Analyzer

Inspect HTTP response headers for missing, weak, or misconfigured security
headers. Returns structured findings with severity levels and actionable
recommendations.

## Quick Start

```php
use Zappzarapp\Security\Headers\Analyzer\SecurityHeaderAnalyzer;

$analyzer = new SecurityHeaderAnalyzer();

$result = $analyzer->analyze([
    'Strict-Transport-Security' => 'max-age=3600',
    'X-Content-Type-Options' => 'nosniff',
]);

foreach ($result->findings() as $finding) {
    printf(
        "[%s] %s: %s\n  -> %s\n",
        strtoupper($finding->severity->value),
        $finding->header,
        $finding->message,
        $finding->recommendation,
    );
}
```

## Classes

| Class                      | Description                                    |
| -------------------------- | ---------------------------------------------- |
| `SecurityHeaderAnalyzer`   | Analyzes headers and returns findings          |
| `AnalysisResult`           | Immutable collection of findings               |
| `Finding`                  | Single issue with header, severity, and advice |
| `FindingSeverity`          | Enum: CRITICAL, HIGH, MEDIUM, LOW, INFO        |

## Severity Levels

| Level    | Meaning                                                   |
| -------- | --------------------------------------------------------- |
| CRITICAL | Immediate security risk                                   |
| HIGH     | Missing essential header or dangerous misconfiguration     |
| MEDIUM   | Suboptimal configuration that weakens security             |
| LOW      | Missing recommended header with limited impact             |
| INFO     | Optional header not present, informational only            |

## Checks

### Strict-Transport-Security (HSTS)

- Missing header (HIGH)
- max-age below 1 year (MEDIUM)
- Missing includeSubDomains (MEDIUM)

### Content-Security-Policy (CSP)

- Missing header (HIGH)
- `unsafe-inline` in script-src (HIGH)
- `unsafe-eval` in script-src (HIGH)
- `unsafe-inline` in style-src (MEDIUM)
- Wildcard `*` source in any directive (HIGH)
- Missing default-src (MEDIUM)

### X-Frame-Options

- Missing header (MEDIUM)

### X-Content-Type-Options

- Missing header (MEDIUM)
- Value other than `nosniff` (MEDIUM)

### Referrer-Policy

- Missing header (LOW)
- `unsafe-url` policy (HIGH)
- `no-referrer-when-downgrade` policy (LOW)

### Permissions-Policy

- Missing header (LOW)

### Cross-Origin Headers (COOP, COEP, CORP)

- Missing COOP (LOW)
- Missing COEP (INFO)
- Missing CORP (INFO)

## Working with Results

```php
$result = $analyzer->analyze($headers);

// Check severity thresholds
if ($result->hasHighOrAbove()) {
    // Fail CI pipeline or raise alert
}

// Filter by header
$hstsIssues = $result->forHeader('Strict-Transport-Security');

// Check if everything is secure
if ($result->isClean()) {
    // All headers properly configured
}

// Count total findings
echo $result->count() . ' issues found';
```

## CI Integration

Use the analyzer in CI pipelines to enforce security header policies:

```php
$result = $analyzer->analyze($headers);

if ($result->hasHighOrAbove()) {
    foreach ($result->findings() as $finding) {
        fwrite(STDERR, sprintf(
            "[%s] %s: %s\n",
            $finding->severity->value,
            $finding->header,
            $finding->message,
        ));
    }

    exit(1);
}
```
