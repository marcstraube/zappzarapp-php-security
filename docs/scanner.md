# Scanner

CLI security header scanner: scan any URL's HTTP response headers with the
[Analyzer](analyzer.md) and get a CI-friendly report - no PHP code required.

## Quick Start

```bash
vendor/bin/security-scan https://example.com
```

```text
Security header scan for https://example.com

[HIGH] Strict-Transport-Security: HSTS header is missing
  fix: Add Strict-Transport-Security with max-age >= 31536000
[MEDIUM] X-Frame-Options: Header is missing
  fix: Add X-Frame-Options: DENY

2 finding(s): 1 high, 1 medium
```

## Options

| Option       | Effect                             |
| ------------ | ---------------------------------- |
| `--json`     | Machine-readable JSON report       |
| `--no-color` | Disable ANSI colors in text output |
| `-h, --help` | Show usage                         |

## Exit Codes

| Code | Meaning                                         |
| ---- | ----------------------------------------------- |
| 0    | Scan passed (nothing of severity HIGH or above) |
| 1    | Findings of severity HIGH or above              |
| 2    | Usage error (missing URL, unknown option)       |
| 3    | Scan failed (invalid URL or network error)      |

MEDIUM and below do not fail the scan - they are reported for review but rarely
warrant breaking a pipeline. Severity assignment is the
[Analyzer](analyzer.md)'s.

## CI Integration

The exit code makes the scanner a one-line CI gate:

```yaml
# GitHub Actions
- name: Scan security headers
  run: vendor/bin/security-scan --no-color https://staging.example.com
```

For automated processing, use JSON output:

```bash
vendor/bin/security-scan --json https://example.com | jq '.summary'
```

```json
{
  "url": "https://example.com",
  "passed": false,
  "findings": [
    {
      "header": "Strict-Transport-Security",
      "severity": "high",
      "message": "HSTS header is missing",
      "recommendation": "Add Strict-Transport-Security with max-age >= 31536000"
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0,
      "info": 0
    }
  }
}
```

## Behavior

- Performs a GET request and follows up to five redirects; the **final**
  response's headers are analyzed.
- Error responses (4xx/5xx) are scanned like any other response - their security
  headers matter too.
- Only `http://` and `https://` URLs are accepted.
- Timeout is 10 seconds.

## Classes

The scanner is also usable programmatically:

| Class                    | Description                                 |
| ------------------------ | ------------------------------------------- |
| `ScanCommand`            | Argument parsing, orchestration, exit codes |
| `StreamHeaderFetcher`    | Fetches response headers via PHP streams    |
| `HeaderFetcherInterface` | Swap in your own HTTP client                |
| `TextScanFormatter`      | Human-readable report with ANSI colors      |
| `JsonScanFormatter`      | JSON report                                 |

```php
use Zappzarapp\Security\Scanner\ScanCommand;

$exitCode = (new ScanCommand())->run(
    ['--json', 'https://example.com'],
    fn(string $out) => fwrite(STDOUT, $out),
    fn(string $err) => fwrite(STDERR, $err),
);
```

## Security Considerations

The fetcher is designed for CLI use, where the operator picks the target
deliberately. Do not wire it to user-supplied URLs in a web application without
SSRF protection - use the [Sanitization](sanitization.md) module's
`UriSanitizer` in that scenario.
