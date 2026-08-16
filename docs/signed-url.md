# Signed URLs

Generate and verify HMAC-SHA-256 signed URLs with mandatory expiry - for
download links, email confirmation links, webhook callbacks, and any other URL
that must not be forged or altered.

## Quick Start

```php
use Zappzarapp\Security\SignedUrl\SigningKey;
use Zappzarapp\Security\SignedUrl\UrlSigner;

$signer = new UrlSigner(SigningKey::generate());

// Sign a URL, valid for one hour
$signed = $signer->sign('https://example.com/download?file=report.pdf', 3600);
// https://example.com/download?file=report.pdf&zzp_expires=...&zzp_signature=...

// Verify - throws on tampering, expiry, or malformed input
$signer->verify($signed);
```

## Classes

| Class        | Description                                |
| ------------ | ------------------------------------------ |
| `UrlSigner`  | Signs and verifies URLs                    |
| `SigningKey` | Leak-resistant HMAC key (minimum 32 bytes) |

## Key Management

```php
use Zappzarapp\Security\Secrets\SecretLoader;
use Zappzarapp\Security\SignedUrl\SigningKey;

// Generate once and store base64-encoded
$key = SigningKey::generate();
file_put_contents('/run/secrets/url_signing_key', $key->toBase64());

// Load via the Secrets module
$key = SigningKey::fromSecretValue(SecretLoader::docker()->load('url_signing_key'));

// Or directly from base64
$key = SigningKey::fromBase64($encoded);
```

`SigningKey` wraps the key material in a `SecretValue`: debug output and
`json_encode()` are redacted, `serialize()` throws, and the buffer is zeroed on
destruction. Keys must be at least 32 bytes (the HMAC-SHA-256 output size);
longer keys are accepted.

## Mandatory Expiry

Every signed URL expires. There deliberately is **no** way to sign a URL without
an expiry: a signed URL is a bearer capability, and an unbounded one is a
credential that can never be revoked. Long-lived links must pass an explicitly
long lifetime, which keeps that decision visible at the call site:

```php
// Valid for 30 days - explicit and reviewable
$signed = $signer->sign($url, 30 * 24 * 3600);
```

The URL is valid up to and including the expiry timestamp. Lifetimes are capped
at `UrlSigner::MAX_LIFETIME_SECONDS` (100 years) as an integer overflow guard.

## Context Binding

Bind a URL to a context value (user id, IP address, session id) without exposing
it in the URL - verification then requires the same context:

```php
$signed = $signer->sign('https://example.com/invoice/42', 3600, context: 'user:1337');

$signer->verify($signed, context: 'user:1337'); // ok
$signer->verify($signed, context: 'user:1338'); // InvalidSignatureException
$signer->verify($signed);                       // InvalidSignatureException
```

## Verification Failures

`verify()` distinguishes failure modes with typed exceptions:

| Exception                   | Meaning                                                             |
| --------------------------- | ------------------------------------------------------------------- |
| `InvalidUrlException`       | Malformed URL, unsupported scheme, bad/missing/duplicate parameters |
| `InvalidSignatureException` | Signature does not match (tampering, wrong key, or context)         |
| `UrlExpiredException`       | Signature is valid, but the expiry timestamp has passed             |
| `InvalidContextException`   | Context value contains control characters                           |

The signature is always checked **before** the expiry, so unauthenticated input
reveals nothing about timestamp validity. Verification is total over
attacker-controlled input: no URL string, however malformed, causes a PHP
warning or error.

```php
use Zappzarapp\Security\SignedUrl\Exception\InvalidSignatureException;
use Zappzarapp\Security\SignedUrl\Exception\InvalidUrlException;
use Zappzarapp\Security\SignedUrl\Exception\UrlExpiredException;

try {
    $signer->verify($url, $context);
} catch (UrlExpiredException) {
    // offer to re-send the link
} catch (InvalidSignatureException | InvalidUrlException) {
    // treat as forged - log and reject
}
```

## Deterministic Time

`UrlSigner` accepts an optional PSR-20 clock, mirroring `SessionGuard` - inject
a frozen clock in tests instead of sleeping:

```php
$signer = new UrlSigner($key, $clock); // Psr\Clock\ClockInterface
```

## What the Signature Covers

The signature covers the scheme, host, effective port, path, and every query
parameter in its original position - adding, removing, changing, or
**reordering** any parameter invalidates it. Parameter order is bound on
purpose: the signer produces the URL and the verifier receives it back, and
order-tolerance would let an attacker reorder repeated keys (`?a=1&a=2` vs
`?a=2&a=1`) unnoticed by last-wins parsers or PHP array parameters.

Semantically equivalent URLs still verify interchangeably:

- Scheme and host are matched case-insensitively
- `http://host` equals `http://host:80`, `https://host` equals
  `https://host:443`
- An empty path equals `/`
- Equivalent percent-encodings match (`%41` equals `A`); `+` is **not** treated
  as a space

Order binding applies to the **non-reserved** parameters. The reserved query
parameters `zzp_expires` and `zzp_signature` are stripped before
canonicalization: they are consumed by the verifier, so their position within
the query string is semantically irrelevant and deliberately not covered by the
signature (cf. AWS SigV4). URLs that already carry them cannot be signed, and
signed URLs carrying either more than once are rejected.

A key without an `=` separator (`?flag`) and a key with an empty value
(`?flag=`) are distinct in the MAC input - mutating one into the other
invalidates the signature.

The exact MAC input encoding (length-prefixed components, version tag
`zappzarapp-signed-url-v1`) is documented as a wire contract in the `UrlSigner`
class docblock and pinned by known-answer tests.

## Restrictions

- Only absolute `http` and `https` URLs can be signed and verified
- URLs with user info (`user:pass@host`) are rejected
- URLs with fragments are rejected - fragments are not sent to the server and
  cannot be protected by the signature
- Control characters (including `\r` and `\n`) in URLs and context values are
  rejected (header injection guard)
- Malformed percent-encoding (a `%` not followed by two hex digits) in the path
  or query is rejected - `rawurldecode()` would leave such sequences untouched,
  making the URL string malleable
- The expiry parameter must be in canonical decimal form - leading zeros are
  rejected for the same reason

## Security Considerations

1. **Use HTTPS** - signed URLs are bearer tokens; anyone who sees one can use it
   until it expires
2. **Keep lifetimes short** - minutes to hours for downloads, at most days for
   email links
3. **Bind to context where possible** - a URL bound to a user id is useless when
   leaked to someone else
4. **Store the key outside the codebase** - use the Secrets module
5. **Rotate keys** - rotating the signing key invalidates all outstanding signed
   URLs at once
6. **Constant-time comparison** - signatures are compared with `hash_equals()`,
   so verification does not leak matching prefixes
