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

| Class                | Description                                               |
| -------------------- | --------------------------------------------------------- |
| `SymmetricEncryptor` | XChaCha20-Poly1305 authenticated encryption               |
| `EncryptionKey`      | 32-byte key, leak-resistant via `SecretValue` composition |
| `Ciphertext`         | Nonce + authenticated payload, versioned string form      |
| `EnvelopeEncryptor`  | Per-message data keys wrapped by a key encryption key     |
| `EnvelopeCiphertext` | Wrapped data key + encrypted payload                      |

## Exceptions

| Exception                    | Thrown when                                          |
| ---------------------------- | ---------------------------------------------------- |
| `DecryptionException`        | Authentication fails (wrong key, tampering, bad AAD) |
| `InvalidKeyException`        | Key material has wrong length or encoding            |
| `InvalidCiphertextException` | Ciphertext fails structural validation before crypto |

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
  convert old data explicitly.

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
4. **Plan for rotation** - store the key version alongside the data or rely on
   the envelope pattern, and decrypt-reencrypt on read after a rotation.
