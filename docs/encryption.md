# Encryption

Sodium-based authenticated encryption with secure defaults: XChaCha20-Poly1305
symmetric encryption, leak-resistant key handling, and envelope encryption for
key-rotation-friendly storage.

There are no negotiable algorithm choices - one modern AEAD cipher, no insecure
fallbacks.

## Quick Start

```php
use Zappzarapp\Security\Encryption\Ciphertext;
use Zappzarapp\Security\Encryption\EncryptionKey;
use Zappzarapp\Security\Encryption\SymmetricEncryptor;

$encryptor = new SymmetricEncryptor();
$key       = EncryptionKey::generate();

$ciphertext = $encryptor->encrypt('sensitive data', $key);
$stored     = $ciphertext->toString(); // "v1.<base64>"

$plaintext = $encryptor->decrypt(Ciphertext::fromString($stored), $key);
```

Loading the key from a Docker secret via the [Secrets](secrets.md) module:

```php
use Zappzarapp\Security\Encryption\EncryptionKey;
use Zappzarapp\Security\Secrets\SecretLoader;

// Provision once: store the base64-encoded key as a secret
// echo "$(php -r 'echo Zappzarapp\Security\Encryption\EncryptionKey::generate()->toBase64();')" > app_key

$key = EncryptionKey::fromSecretValue(SecretLoader::docker()->load('app_key'));
```

## Classes

| Class                         | Description                                               |
| ----------------------------- | --------------------------------------------------------- |
| `SymmetricEncryptor`          | XChaCha20-Poly1305 authenticated encryption               |
| `EncryptionKey`               | 32-byte key, leak-resistant via `SecretValue` composition |
| `Ciphertext`                  | Nonce + authenticated payload, versioned string form      |
| `EnvelopeEncryptor`           | Per-message data keys wrapped by a key encryption key     |
| `EnvelopeCiphertext`          | Wrapped data key + encrypted payload                      |
| `KeyRing`                     | Versioned keys with one active key, enables rotation      |
| `KeyRingEncryptor`            | Symmetric encryption against a key ring                   |
| `KeyRingEnvelopeEncryptor`    | Envelope encryption against a key ring, cheap re-wrap     |
| `VersionedCiphertext`         | Ciphertext stamped with its key version                   |
| `VersionedEnvelopeCiphertext` | Envelope with a versioned wrapped data key                |

## Exceptions

| Exception                    | Thrown when                                          |
| ---------------------------- | ---------------------------------------------------- |
| `DecryptionException`        | Authentication fails (wrong key, tampering, bad AAD) |
| `InvalidKeyException`        | Key material has wrong length or encoding            |
| `InvalidCiphertextException` | Ciphertext fails structural validation before crypto |
| `InvalidKeyRingException`    | Key ring fails structural validation                 |
| `UnknownKeyVersionException` | Ciphertext references a key version not in the ring  |

## Secure Defaults

- **Single algorithm.** XChaCha20-Poly1305 only - no cipher negotiation, no
  downgrade path, no ECB/CBC foot-guns.
- **Random nonces are safe.** XChaCha20's 24-byte nonce makes random nonce
  collision statistically negligible; there is no counter state to persist or
  corrupt.
- **Authenticated by construction.** Tampering, truncation, or a wrong key throw
  `DecryptionException` before any plaintext is released. The error message
  deliberately does not reveal _why_ decryption failed.
- **Keys are leak-resistant.** `EncryptionKey` wraps its material in a
  `SecretValue`: redacted in `var_dump()` and `json_encode()`, `serialize()`
  throws, and the buffer is zeroed via `sodium_memzero()` on destruction.
- **Versioned wire format.** Ciphertexts serialize as `v1.<base64>` (envelopes
  as `e1.<base64>`), so a future algorithm migration can detect and reject or
  convert old data explicitly. Key-ring ciphertexts additionally carry their key
  version: `v2.<version>.<base64>` and `e2.<version>.<base64>`.

## Additional Data (AAD)

Bind a ciphertext to its context so it cannot be replayed elsewhere - for
example, moving an encrypted value from one user's row to another:

```php
$ciphertext = $encryptor->encrypt($ssn, $key, additionalData: 'user:' . $userId);

// Decryption fails if the context does not match:
$encryptor->decrypt($ciphertext, $key, additionalData: 'user:' . $userId);
```

The additional data is authenticated but not encrypted - it is not stored in the
ciphertext and must be supplied again on decryption.

## Envelope Encryption

For data at rest, prefer envelope encryption: each `seal()` generates a fresh
data encryption key (DEK), encrypts the payload with it, and wraps the DEK with
your long-lived key encryption key (KEK).

```php
use Zappzarapp\Security\Encryption\EnvelopeCiphertext;
use Zappzarapp\Security\Encryption\EnvelopeEncryptor;

$envelope = new EnvelopeEncryptor();
$kek      = EncryptionKey::fromSecretValue(SecretLoader::docker()->load('app_kek'));

$sealed = $envelope->seal($document, $kek, additionalData: 'doc:' . $documentId);
$stored = $sealed->toString(); // "e1.<base64>"

$document = $envelope->open(
    EnvelopeCiphertext::fromString($stored),
    $kek,
    additionalData: 'doc:' . $documentId
);
```

Why envelope encryption:

- **Cheap KEK rotation** - re-wrap the 72-byte wrapped keys instead of
  re-encrypting every payload.
- **KEK exposure is bounded** - the KEK only ever encrypts 32-byte random keys,
  never attacker-influenced plaintext.
- **KMS-compatible** - the wrapped key can be handed to an external key
  management service for re-wrapping.

The additional data is bound to both the payload and the wrapped key, so neither
part can be swapped between envelopes.

## Key Rotation

Rotating a single key means losing access to old ciphertexts. A `KeyRing` holds
multiple versioned keys - the active one encrypts, all of them decrypt - so
rotation becomes routine instead of a migration project:

```php
use Zappzarapp\Security\Encryption\KeyRing;
use Zappzarapp\Security\Encryption\KeyRingEncryptor;
use Zappzarapp\Security\Encryption\VersionedCiphertext;

$ring = KeyRing::fromKeys([
    1 => EncryptionKey::fromBase64($oldEncoded),
    2 => EncryptionKey::fromBase64($newEncoded),
], activeVersion: 2);

$encryptor = new KeyRingEncryptor($ring);

$stored = $encryptor->encrypt($ssn, additionalData: 'user:42')->toString(); // "v2.2.<base64>"

// Later - decryption picks the right key by the version in the ciphertext:
$ciphertext = VersionedCiphertext::fromString($stored);
$ssn        = $encryptor->decrypt($ciphertext, additionalData: 'user:42');

// Lazy migration on read:
if ($encryptor->needsRotation($ciphertext)) {
    $stored = $encryptor->rotate($ciphertext, additionalData: 'user:42')->toString();
}
```

The rotation lifecycle:

1. **Provision** a new key and activate it: `$ring->withRotatedKey($newKey)`.
   New data is encrypted under the new version; old data stays readable.
2. **Migrate** lazily via `rotate()` (or `rewrap()` for envelopes) whenever a
   ciphertext with an outdated version passes through.
3. **Retire** the old key once nothing references it: `$ring->withoutKey(1)`.
   Ciphertexts still using it now fail with `UnknownKeyVersionException` - a
   distinct error, never a silent fallback.

For envelopes, `KeyRingEnvelopeEncryptor::rewrap()` is where the envelope
pattern pays off: only the 72-byte wrapped data key is re-encrypted, the payload
bytes are reused untouched.

```php
use Zappzarapp\Security\Encryption\KeyRingEnvelopeEncryptor;
use Zappzarapp\Security\Encryption\VersionedEnvelopeCiphertext;

$envelope = new KeyRingEnvelopeEncryptor($ring);

$sealed = $envelope->seal($document, additionalData: 'doc:17'); // "e2.2.<base64>"

if ($envelope->needsRotation($sealed)) {
    $sealed = $envelope->rewrap($sealed, additionalData: 'doc:17'); // payload untouched
}
```

Details:

- **Version binding.** The key version is bound into the additional data (4-byte
  big-endian prefix), so a re-stamped version header fails authentication even
  if both versions hold identical key material.
- **Domain separation.** Wrapped data keys carry a fixed `zzp:dek-wrap\0` label
  in their additional data, so a wrapped key can never authenticate as an
  ordinary `v2.` ciphertext (or vice versa), even when both encryptors share one
  ring and one additional data value. Do not start your own additional data with
  that reserved label.
- **No version reuse.** Retiring the highest key does not free its number; the
  next rotation still gets a fresh version, so retired-version ciphertexts keep
  failing with `UnknownKeyVersionException`.
- **Legacy migration.** Version-less `v1.`/`e1.` ciphertexts from before key
  rotation decrypt via `decryptLegacy()`/`openLegacy()` with the ring's
  **oldest** key, and migrate via `rotateLegacy()`/`rewrapLegacy()`. Provision
  the pre-ring key as the lowest version.
- **Strict versions.** Key versions are integers between 1 and 999999999, parsed
  strictly from the wire format - no user-controlled strings.

## Key Management

```php
// Generate and provision (once, outside the application)
$key = EncryptionKey::generate();
echo $key->toBase64(); // store as Docker secret / in your KMS

// Load at bootstrap
$key = EncryptionKey::fromSecretValue($loader->load('app_key'));

// Or directly from base64
$key = EncryptionKey::fromBase64($encodedKey);
```

Secrets store the key **base64-encoded** (raw key bytes would not survive the
secret file newline-trimming convention).

## Best Practices

1. **Use envelope encryption for stored data** - direct symmetric encryption is
   fine for transient values (cache entries, queue messages); anything
   long-lived benefits from cheap key rotation.
2. **Always pass additional data when the ciphertext belongs to a record** - it
   prevents an attacker with database write access from swapping ciphertexts
   between rows.
3. **Keep keys out of the codebase** - load them via the [Secrets](secrets.md)
   module or a KMS, never from committed configuration.
4. **Plan for rotation** - use a `KeyRing` from the start: `KeyRing::create()`
   costs nothing today and makes the first real rotation a one-line change
   instead of a data migration.
