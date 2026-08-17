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

One entry point per concern; the classes each of them builds on are listed in
the section below it.

| Class             | Description                                            |
| ----------------- | ------------------------------------------------------ |
| `HtmlSanitizer`   | Sanitizes HTML, removing dangerous elements/attributes |
| `UriSanitizer`    | Validates and sanitizes URIs                           |
| `PathValidator`   | Prevents path traversal attacks                        |
| `UploadValidator` | Allow-list based file upload validation                |

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

## Path Validation

Detects directory traversal (`../`, `..\`), null bytes and percent-encoded
traversal sequences, and confines paths to a base directory.

```php
use Zappzarapp\Security\Sanitization\Path\PathValidationConfig;
use Zappzarapp\Security\Sanitization\Path\PathValidator;

$validator = new PathValidator(new PathValidationConfig(basePath: '/var/www/uploads'));

// Throws PathTraversalException
$validator->validate('/var/www/uploads/../../etc/passwd');

// Or decide without an exception
if ($validator->isSafe($path)) {
    // ...
}
```

`validate()` throws, `isSafe()` answers the same question as a boolean, and
`normalize()` validates first and then collapses separators and redundant
slashes.

### Configuration

| Option              | Default | Effect                                                       |
| ------------------- | ------- | ------------------------------------------------------------ |
| `basePath`          | `null`  | Confines paths to this directory, resolved with `realpath()` |
| `allowDotFiles`     | `false` | Rejects hidden files such as `.htaccess`                     |
| `allowSymlinks`     | `false` | Rejects a symlink anywhere in the path                       |
| `normalizePath`     | `true`  | Lets `normalize()` clean up separators and slashes           |
| `blockedExtensions` | `[]`    | Rejects these extensions, matched case-insensitively         |

With a `basePath` configured, paths are resolved through `realpath()` and must
therefore be absolute; a relative path resolves against the working directory
and will not match the base. For a file that does not exist yet the parent
directory is resolved instead, so a path for something about to be written
validates.

Path validation cannot be free of TOCTOU races: the filesystem may change
between the check and the file operation. Where that matters, add file locking
or perform the operation atomically.

## File Upload Validation

Uploads are a standard way in: a PHP script named `avatar.jpg`, a filename that
escapes the upload directory, a `Content-Type` the client made up.
`UploadValidator` checks the bytes that actually arrived and never what the
client asserted about them.

```php
use Zappzarapp\Security\Sanitization\Upload\UploadConstraints;
use Zappzarapp\Security\Sanitization\Upload\UploadValidator;

$validator = new UploadValidator(UploadConstraints::images());

// Native $_FILES
$upload = $validator->validateNativeUpload($_FILES['avatar']);

// PSR-7
$upload = $validator->validateUploadedFile($request->getUploadedFiles()['avatar']);

$upload->filename;   // "holiday_photo.jpg" - sanitized, no directory components
$upload->extension;  // "jpg" - the matched allow-list key
$upload->mimeType;   // "image/jpeg" - detected from the content
$upload->sizeBytes;  // the real byte count
```

`validateNativeUpload()` takes exactly one `$_FILES` entry. A multi-file field
(`<input type="file" name="docs[]">`) produces a single entry whose `name`,
`tmp_name` and `error` are arrays; split it into per-file entries first, because
passing it as-is is rejected as a malformed entry rather than silently
validating only the first file.

### Classes

| Class                       | Description                                   |
| --------------------------- | --------------------------------------------- |
| `UploadValidator`           | Validates `$_FILES` entries and PSR-7 uploads |
| `UploadConstraints`         | Allow-list, size limit and filename options   |
| `ValidatedUpload`           | Result: filename, extension, MIME type, size  |
| `FilenameSanitizer`         | Client filename to safe storage filename      |
| `UploadErrorCode`           | The `UPLOAD_ERR_*` codes as an enum           |
| `FinfoMimeTypeDetector`     | Content sniffing via `ext-fileinfo`           |
| `NativeUploadedFileChecker` | `is_uploaded_file()` behind an interface      |

### What Gets Checked

1. The `UPLOAD_ERR_*` code reports success.
2. For native uploads, `is_uploaded_file()` confirms PHP created the temporary
   file - a forged `tmp_name` cannot point the validator at `/etc/passwd`.
3. The real byte count is within the limit. The size the client reported is
   ignored.
4. The filename survives `FilenameSanitizer`.
5. A suffix of the filename is on the extension allow-list, and nothing in front
   of it looks like a further extension.
6. The MIME type detected from the content is one of the types mapped to that
   extension.

### The Allow-List

There is no permissive default. `UploadConstraints` requires an allow-list that
maps every accepted extension to the MIME types content sniffing may report for
it, and constructing it with an empty list throws:

```php
$constraints = new UploadConstraints(
    allowedTypes: [
        'pdf' => ['application/pdf'],
        'csv' => ['text/csv', 'text/plain'],
    ],
    maxSizeBytes: 2 * 1024 * 1024,
);
```

Extensions and MIME types are matched case-insensitively; both are lowercased
when the constraints are built, and a leading dot in a key is optional.

Two presets are available. `UploadConstraints::images()` covers jpg, jpeg, png,
gif and webp - deliberately not SVG, which is an XML document that can carry
script. `UploadConstraints::documents()` covers pdf, txt and csv - deliberately
not the ZIP based office formats, because content sniffing reports them as
`application/zip` and allowing them means allowing every ZIP archive.

Every modifier returns a new instance:

```php
$constraints = UploadConstraints::images()
    ->withMaxSizeBytes(512_000)
    ->withMaxFilenameLength(120);
```

### Extensions and Double Extensions

The longest matching suffix wins, and by default the remaining stem must not
contain another dot:

| Filename           | Allow-list | Result                       |
| ------------------ | ---------- | ---------------------------- |
| `photo.jpg`        | `jpg`      | accepted, extension `jpg`    |
| `shell.php.jpg`    | `jpg`      | rejected, two extensions     |
| `archive.tar.gz`   | `tar.gz`   | accepted, extension `tar.gz` |
| `archive.tar.gz`   | `gz`       | rejected, two extensions     |
| `invoice.2024.pdf` | `pdf`      | rejected, two extensions     |

So `archive.tar.gz` keeps working - but only if the compound extension `tar.gz`
is registered explicitly, which is exactly the decision that distinguishes it
from `shell.php.jpg`. Names with an incidental second dot such as
`invoice.2024.pdf` are rejected by the same rule; accept them with
`withMultipleExtensions()`, which also re-admits `shell.php.pdf`.

### Filename Sanitization

`FilenameSanitizer` rejects what can never be legitimate and transforms what
merely needs to be made safe:

| Input                                    | Result                              |
| ---------------------------------------- | ----------------------------------- |
| NUL byte, control character              | rejected                            |
| invalid UTF-8                            | rejected                            |
| bidi override, zero width character      | rejected                            |
| `..`, `.`                                | rejected                            |
| `CON`, `NUL`, `COM1` ... `LPT9`          | rejected                            |
| longer than the limit (255 bytes)        | rejected                            |
| directory components                     | stripped: `a/b/c.png` -> `c.png`    |
| leading dots                             | stripped: `.htaccess` -> `htaccess` |
| trailing dots and spaces                 | stripped: `evil.php.` -> `evil.php` |
| everything else outside `[A-Za-z0-9._-]` | replaced with `_`                   |

The result is always a bare filename, safe in a path, in a shell word, in a
header value and in a log line. Both separators are stripped, so a Windows
client cannot smuggle a directory through `C:\Users\bob\evil.php`.

Unicode filenames are an explicit opt-in. With `withUnicodeFilenames()` the name
is NFC-normalized and letters, marks and digits are kept - bidirectional and
zero-width characters stay rejected either way.

```php
$sanitizer = new FilenameSanitizer();

$sanitizer->sanitize('../../etc/passwd');   // "passwd"
$sanitizer->sanitize('My Report (1).pdf');  // "My_Report__1_.pdf"
$sanitizer->sanitize('.htaccess');          // "htaccess"
```

### Failures

`validateNativeUpload()` and `validateUploadedFile()` throw
`InvalidUploadException` when the upload is rejected and
`InvalidFilenameException` when no safe filename can be derived. Both messages
are built exclusively from validated values, so they are safe to log:

```php
use Zappzarapp\Security\Sanitization\Exception\InvalidFilenameException;
use Zappzarapp\Security\Sanitization\Exception\InvalidUploadException;

try {
    $upload = $validator->validateNativeUpload($_FILES['avatar']);
} catch (InvalidUploadException | InvalidFilenameException $e) {
    // rejected
}

// Or check without exceptions
if ($validator->isValidNativeUpload($_FILES['avatar'])) {
    // ...
}
```

Pass a `SecurityLoggerInterface` as the second constructor argument to record
every rejection as a warning:

```php
$validator = new UploadValidator(UploadConstraints::images(), $logger);
```

### Requirements and Limits

`ext-fileinfo` is required - it is what makes content based detection possible,
and without it the validator would have to fall back to trusting the client.

Validation is a check on bytes at a point in time, not a guarantee about the
file afterwards:

- **TOCTOU.** Between validation and `move_uploaded_file()` the temporary file
  can still change if the temporary directory is writable by other users. Move
  the file first and validate the moved copy, or keep the upload directory
  private to the process.
- **Polyglots.** A file can be a valid GIF and valid PHP at the same time.
  Sniffing reports the leading format. Never store uploads inside the web root
  and never let the web server execute them.
- **Container formats.** docx, xlsx, odt and jar are ZIP archives and sniff as
  `application/zip`.
- **Malware.** No signature scanning is performed.
- **Memory.** PSR-7 uploads are buffered in memory for sniffing, bounded by the
  configured maximum size plus one 8 KiB read chunk.

## Security Considerations

1. **Sanitize on output, validate on input** - Sanitization is your last line of
   defense
2. **Context matters** - HTML sanitization is different from SQL escaping
3. **Allowlist, don't blocklist** - Allow known-good elements/schemes
4. **Don't trust sanitizers alone** - Use CSP headers as defense in depth
5. **Test with payloads** - Use OWASP XSS filter evasion cheat sheet
6. **Log blocked content** - Track attack attempts for monitoring
7. **Store uploads outside the web root** - Validation cannot stop code that the
   web server is willing to execute
