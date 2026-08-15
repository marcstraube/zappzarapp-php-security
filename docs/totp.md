# TOTP

Time-based one-time passwords per RFC 6238 (on an RFC 4226 HOTP foundation):
secret provisioning for authenticator apps, code verification with replay
protection, and hashed single-use recovery codes.

## Quick Start

```php
use Zappzarapp\Security\Totp\ProvisioningUri;
use Zappzarapp\Security\Totp\TotpAuthenticator;
use Zappzarapp\Security\Totp\TotpSecret;

$totp = new TotpAuthenticator();

// Enrollment: generate a secret, show it as QR code once, store it encrypted
$secret = TotpSecret::generate();
$qrPayload = new ProvisioningUri('Example App', 'marc@example.com', $secret)->toString();

// Login: verify the submitted code
$result = $totp->verify($secret, $submittedCode, lastAcceptedTimeStep: $user->lastTotpStep);

if ($result->valid) {
    $user->lastTotpStep = $result->matchedTimeStep; // persist - blocks replay
}
```

## Classes

| Class                    | Description                                              |
| ------------------------ | -------------------------------------------------------- |
| `TotpAuthenticator`      | Code generation and verification (RFC 6238)              |
| `TotpSecret`             | ≥160-bit shared secret, leak-resistant via `SecretValue` |
| `TotpConfig`             | Period, digits, algorithm, verification window           |
| `TotpAlgorithm`          | SHA-1 (default), SHA-256, SHA-512                        |
| `TotpVerificationResult` | Verification outcome with the matched time step          |
| `ProvisioningUri`        | `otpauth://` Key Uri for authenticator app enrollment    |
| `HotpGenerator`          | RFC 4226 HOTP foundation                                 |
| `Base32`                 | Strict RFC 4648 codec for secret provisioning            |
| `RecoveryCode`           | Single-use recovery code (plain text, show once)         |
| `RecoveryCodeGenerator`  | Cryptographically random code generation                 |
| `RecoveryCodeVerifier`   | Argon2id hashing and one-time verification               |

## Exceptions

| Exception                          | Thrown when                                    |
| ---------------------------------- | ---------------------------------------------- |
| `InvalidTotpSecretException`       | Secret shorter than 160 bit                    |
| `InvalidTotpConfigException`       | Period/digits/window/timestamp/counter invalid |
| `InvalidBase32Exception`           | Base32 input fails strict decoding             |
| `InvalidProvisioningDataException` | Issuer or account name invalid                 |
| `InvalidRecoveryCodeException`     | Recovery code count out of range               |

## Secure Defaults

- **RFC-standard parameters.** 30-second period, 6 digits, SHA-1 - the only
  combination universally supported by authenticator apps. SHA-256/512 are
  explicit opt-in for controlled clients.
- **±1 step verification window.** Tolerates clock drift of one period; wider
  windows weaken replay resistance and require explicit `withWindow()`.
- **Replay protection is first-class.** `verify()` skips time steps at or before
  the persisted `lastAcceptedTimeStep`, so an intercepted code cannot be used
  twice. Persist `TotpVerificationResult::$matchedTimeStep` after every success.
- **Constant-time comparison.** Every candidate step is evaluated with
  `hash_equals()` - no early exit on match.
- **Strict input handling.** User codes are length- and digit-checked before any
  secret is touched; base32 decoding rejects non-canonical encodings.
- **Leak-resistant secrets.** `TotpSecret` and `RecoveryCode` wrap their
  material in `SecretValue`: redacted debug output and JSON, `serialize()`
  protection, `sodium_memzero()` on destruction.

## Verification and Replay Protection

```php
$result = $totp->verify(
    $secret,
    $submittedCode,
    lastAcceptedTimeStep: $user->lastTotpStep, // null on first use
    timestamp: null,                           // null = injected clock or time()
);

if ($result->valid) {
    $user->lastTotpStep = $result->matchedTimeStep;
}
```

Passing the persisted step back is what makes each code one-time: codes for that
step (or older) are rejected even inside the verification window. Without it, an
attacker who intercepts a code can reuse it for up to
`(2 * window + 1) * period` seconds.

For deterministic tests, inject a PSR-20 clock:

```php
$totp = new TotpAuthenticator(clock: $frozenClock);
```

## Provisioning

```php
$secret = TotpSecret::generate();                 // 20 bytes for SHA-1
$secret = TotpSecret::generate(TotpAlgorithm::Sha256); // 32 bytes

$uri = new ProvisioningUri('Example App', 'marc@example.com', $secret);
$uri->toString(); // otpauth://totp/Example%20App:marc%40example.com?secret=...
```

Render the URI as a QR code during enrollment. The URI contains the secret -
treat it like the secret itself: display once, never log or persist it. Store
the secret encrypted (see [Encryption](encryption.md)); `toBase32()` /
`fromBase32()` provide the transport form.

Complete the enrollment only after the user has verified one code - that proves
the authenticator actually holds the secret.

## Recovery Codes

```php
use Zappzarapp\Security\Totp\Recovery\RecoveryCodeGenerator;
use Zappzarapp\Security\Totp\Recovery\RecoveryCodeVerifier;

$generator = new RecoveryCodeGenerator();
$verifier  = new RecoveryCodeVerifier();

// Enrollment: show the codes once, persist only the hashes
$codes  = $generator->generate();                       // 10 × xxxx-xxxx-xxxx-xxxx
$hashes = array_map($verifier->hash(...), $codes);

// Recovery login: find and consume the matching code
$index = $verifier->verify($submittedCode, $user->recoveryCodeHashes);

if ($index !== null) {
    unset($user->recoveryCodeHashes[$index]); // single use
}
```

Codes carry ~79 bit of entropy from an alphabet without look-alike characters
(no `i`, `l`, `o`, `0`, `1`) and are hashed with Argon2id - a database leak must
not expose usable codes. Input verification ignores case and separators.

## Best Practices

1. **Rate-limit verification endpoints** - combine with the
   [Rate Limiting](rate-limiting.md) module; six digits withstand online
   guessing only when attempts are bounded.
2. **Persist the matched time step** - replay protection only works if
   `matchedTimeStep` round-trips through your storage.
3. **Store secrets encrypted** - TOTP secrets are symmetric; anyone who reads
   them can generate valid codes. Use the [Encryption](encryption.md) module.
4. **Regenerate recovery codes on suspicion** - and show new codes only after
   re-authentication.
