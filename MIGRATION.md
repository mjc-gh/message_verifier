# Migrating from 2.x to 3.0

Version 3 redesigns configuration and adds Rails JSON metadata. Existing raw token
formats remain supported when the same keys, ciphers, digests, and encodings are selected.
Rust 1.89 or newer is required.

## Verifier

`Verifier::new(secret)` still selects HMAC-SHA1 and standard Base64. It now accepts binary
keys. `generate` accepts bytes or strings and returns `String` directly, so remove
`.unwrap()`, `.expect(...)`, or `?` from calls to `generate`.

`verify` returns `Result<Vec<u8>>`; invalid signatures and Base64 return `InvalidSignature`.
Replace `is_valid_message(encoded_data, signature)` with `valid_message(whole_token)`.
Use a builder to select another digest or URL-safe generation:

```rust
use message_verifier::{Digest, Encoding, Verifier};
let verifier = Verifier::builder("secret")
    .digest(Digest::Sha256).encoding(Encoding::UrlSafe).build();
```

## Encryption and key derivation

The `Encryptor` trait, `AesHmacEncryptor`, `AesGcmEncryptor`, `KeySize`,
`DerivedKeyParams`, and `create_derived_keys` are replaced by `Encryptor`, `Cipher`,
and `KeyGenerator`. Keys are derived separately and must be exactly the cipher's key length.

Equivalent to the old `AesHmacEncryptor::new(secret, salt, sign_salt, DerivedKeyParams::default())`:

```rust
use message_verifier::{Cipher, Encryptor, KeyGenerator};
let generator = KeyGenerator::new("helloworld").iterations(1000);
let encryptor = Encryptor::builder(generator.generate_key("test salt", 32)?)
    .cipher(Cipher::Aes256Cbc)
    .signing_key(generator.generate_key("test signed salt", 64)?)
    .build()?;
# Ok::<(), message_verifier::Error>(())
```

Equivalent to the old `AesGcmEncryptor` constructor:

```rust
use message_verifier::{Encryptor, KeyGenerator};
let generator = KeyGenerator::new("helloworld").iterations(1000);
let encryptor = Encryptor::new(generator.generate_key("test salt", 32)?)?;
# Ok::<(), message_verifier::Error>(())
```

For AES-128 or AES-192, select the corresponding `Cipher` and derive 16 or 24 bytes.
Replace mutations of `encryptor.key_size` with constructor-time `.cipher(...)` selection.
CBC still authenticates before decrypting. GCM still uses a 12-byte IV and 16-byte tag.

`KeyGenerator::new` uses SHA1 and 65,536 iterations, matching standalone ActiveSupport.
Keep `.iterations(1000)` for old library keys. Use `KeyGenerator::rails` for Rails 7.0+
application defaults, or set `.digest(...)` and `.iterations(...)` explicitly to match
your application. Changing derivation changes keys: add the old encryptor as a rotation
while migrating existing tokens.

## JSON and errors

Existing raw methods do not deserialize or enforce metadata. Use `generate_json`,
`verify_json`, `verified_json`, `encrypt_and_sign_json`, and `decrypt_and_verify_json`
for purpose and expiration enforcement. Pass Rust values directly, not pre-serialized JSON
strings. Both legacy and current Rails JSON envelopes are read automatically.

Replace `error-chain`'s `ErrorKind` / `.kind()` matches with matches on `message_verifier::Error`.
Verifier rejection maps to `InvalidSignature`. Encryptor authentication and format failures
map to `InvalidMessage`, including a bad CBC signature. JSON serialization failures retain
their Serde source in `Error::Serialization`.

Optional JSON methods distinguish rejected tokens from valid values and serialization
errors using `Result<Option<T>>`. `decrypt_and_verify_json` returns `Ok(None)` on expired
or purpose-mismatched messages, matching Rails' `nil` behavior.

## Rotation

Pass a fully configured old verifier or encryptor to `.rotate(fallback)`. Unlike Ruby's
`rotate`, Rust settings do not implicitly inherit from the primary. All writes use the
primary; remove the fallback after the migration window closes.
