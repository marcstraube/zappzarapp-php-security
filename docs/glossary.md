# Security Glossary

This glossary explains security terms used throughout the library documentation.

## A

### Argon2id

A password hashing algorithm that combines Argon2i (side-channel resistance) and
Argon2d (GPU resistance). It is the recommended choice for password hashing as
of 2024. The algorithm is memory-hard, making it expensive to attack with
specialized hardware.

**Used in:** [Password module](password.md)

## C

### COEP (Cross-Origin-Embedder-Policy)

An HTTP header that prevents a document from loading cross-origin resources that
don't explicitly grant permission. When set to `require-corp`, only resources
with appropriate CORS headers or CORP headers can be loaded.

**Used in:** [Headers module](headers.md)

### COOP (Cross-Origin-Opener-Policy)

An HTTP header that controls whether a document can share a browsing context
group with cross-origin documents. Setting it to `same-origin` isolates the
document from cross-origin popups, preventing Spectre-like attacks.

**Used in:** [Headers module](headers.md)

### CORP (Cross-Origin-Resource-Policy)

An HTTP header that controls which origins can include a resource. Options are
`same-site`, `same-origin`, or `cross-origin`. Helps prevent cross-origin data
leaks.

**Used in:** [Headers module](headers.md)

### CSRF (Cross-Site Request Forgery)

An attack that tricks a user's browser into making unwanted requests to a site
where they're authenticated. Prevented using synchronizer tokens or
double-submit cookies.

**Used in:** [CSRF module](csrf.md)

### CSP (Content Security Policy)

An HTTP header that controls which resources (scripts, styles, images, etc.) a
browser is allowed to load for a page. Mitigates XSS attacks by restricting
inline scripts and untrusted sources.

**Used in:** [CSP module](csp.md)

### CSP Nonce

A cryptographically random, single-use token added to `<script>` and `<style>`
tags. The browser only executes inline scripts/styles whose nonce matches the
one in the CSP header. Provides protection against XSS while allowing necessary
inline code.

**Used in:** [CSP module](csp.md)

## D

### Defense-in-Depth

A security strategy that employs multiple layers of protection. If one layer
fails, others still provide security. This library implements defense-in-depth
by validating inputs at multiple points, using redundant checks, and combining
multiple security mechanisms.

**Example:** Nonces are validated both in `NonceGenerator` and `NonceRegistry`
independently.

### Double-Submit Cookie

A CSRF protection technique where a random token is sent both as a cookie and as
a request parameter. The server verifies that both values match. Since attackers
cannot read cookies from another domain, they cannot forge valid requests.

**Used in:** [CSRF module](csrf.md)

## H

### HIBP (Have I Been Pwned)

A service that aggregates data breaches and allows checking if a password has
appeared in known breaches. This library uses the k-Anonymity API to check
passwords without revealing them to the service.

**Used in:** [Password module](password.md)

### Homograph Attack

An attack using lookalike Unicode characters to create deceptive domain names.
For example, using Cyrillic "а" (U+0430) instead of Latin "a" to create
`аpple.com` that looks like `apple.com`. Also called an IDN homograph attack or
confusable attack.

**Used in:** [Sanitization module](sanitization.md)

### HSTS (HTTP Strict Transport Security)

An HTTP header that tells browsers to only access the site via HTTPS, even if
the user types `http://`. Prevents SSL stripping attacks and protects against
downgrade attacks.

**Used in:** [Headers module](headers.md)

## I

### IDN (Internationalized Domain Name)

A domain name containing non-ASCII characters (e.g., `münchen.de`). IDNs are
encoded using Punycode for DNS compatibility. This library validates IDNs to
prevent homograph attacks.

**Used in:** [Sanitization module](sanitization.md)

## K

### k-Anonymity

A privacy-preserving technique where data is grouped so that each record is
indistinguishable from at least k-1 other records. This library uses k-Anonymity
when checking passwords against HIBP: only the first 5 characters of the SHA-1
hash are sent, returning all matching hashes. The full hash is then compared
locally.

**Used in:** [Password module](password.md)

## M

### Memory Clearing

The practice of overwriting sensitive data in memory after use. This library
uses `sodium_memzero()` (when available) to securely erase passwords from memory
after hashing, reducing the window for memory-scraping attacks.

**Used in:** [Password module](password.md)

## N

### Nonce

A "number used once" - a random value that should only be used for a single
operation. In CSP, nonces identify trusted inline scripts. Nonces must be
unpredictable (cryptographically random) and unique per response.

**Used in:** [CSP module](csp.md)

## P

### Pepper

A secret value added to passwords before hashing, stored separately from the
password hashes (typically in configuration or environment variables). Unlike
salts, peppers are not stored with the hash and must remain secret.

**Used in:** [Password module](password.md)

### Punycode

An encoding scheme that represents Unicode domain names using ASCII characters.
For example, `münchen.de` becomes `xn--mnchen-3ya.de`. Used internally by DNS
and this library for IDN validation.

**Used in:** [Sanitization module](sanitization.md)

## R

### Rate Limiting

A technique to control the rate of requests a client can make. Prevents brute
force attacks, DoS attempts, and API abuse. This library implements token bucket
and sliding window algorithms.

**Used in:** [Rate Limiting module](rate-limiting.md)

## S

### Salt

A random value added to each password before hashing to ensure identical
passwords produce different hashes. Salts are stored alongside the hash and are
automatically handled by PHP's `password_hash()`.

**Used in:** [Password module](password.md)

### Sliding Window

A rate limiting algorithm that tracks requests within a moving time window.
Provides smoother rate limiting than fixed windows by considering request
history.

**Used in:** [Rate Limiting module](rate-limiting.md)

### SRI (Subresource Integrity)

A security feature that allows browsers to verify that resources (scripts,
styles) haven't been tampered with. A cryptographic hash of the expected content
is included in the HTML, and the browser checks the downloaded content against
it.

**Used in:** [SRI module](sri.md)

### SSRF (Server-Side Request Forgery)

An attack that tricks a server into making requests to unintended locations,
potentially accessing internal services or cloud metadata endpoints. This
library blocks private IP ranges and validates URLs before making requests.

**Used in:** [Sanitization module](sanitization.md), [SRI module](sri.md)

### Synchronizer Token

A CSRF protection technique using a secret token stored in the user's session.
The token is included in forms and validated on submission. Since attackers
cannot access the session, they cannot obtain valid tokens.

**Used in:** [CSRF module](csrf.md)

## T

### Token Bucket

A rate limiting algorithm that models a bucket filling with tokens at a steady
rate. Each request consumes a token; if the bucket is empty, the request is
rejected. Allows bursts up to the bucket capacity while maintaining an average
rate.

**Used in:** [Rate Limiting module](rate-limiting.md)

## X

### XSS (Cross-Site Scripting)

An attack that injects malicious scripts into web pages viewed by other users.
Types include:

- **Stored XSS:** Script is permanently stored on the server
- **Reflected XSS:** Script is reflected from a URL parameter
- **DOM-based XSS:** Script manipulates the page's DOM

Prevented using CSP, input sanitization, and output encoding.

**Used in:** [CSP module](csp.md), [Sanitization module](sanitization.md)
