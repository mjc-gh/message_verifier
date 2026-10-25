# message_verifier

[![CI](https://github.com/mjc-gh/message_verifier/actions/workflows/actions.yml/badge.svg)](https://github.com/mjc-gh/message_verifier/actions/workflows/actions.yml)
[![Crates.io](https://img.shields.io/crates/v/message_verifier)](https://crates.io/crates/message_verifier)
[![MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)

Rust message signing and authenticated encryption compatible with Rails and
ActiveSupport's [MessageVerifier](https://api.rubyonrails.org/classes/ActiveSupport/MessageVerifier.html)
and [MessageEncryptor](https://api.rubyonrails.org/classes/ActiveSupport/MessageEncryptor.html).
Requires Rust **1.89** or newer. [API documentation](https://docs.rs/message_verifier).

## Sign JSON with a purpose and expiration

```rust
use std::time::Duration;
use message_verifier::{Digest, Encoding, MessageOptions, Verifier, VerifyOptions};
use serde_json::{json, Value};

let verifier = Verifier::builder("a signing secret")
    .digest(Digest::Sha256)
    .encoding(Encoding::UrlSafe)
    .build();

let token = verifier.generate_json(&json!({"user_id": 42}), MessageOptions {
    purpose: Some("login"),
    expires_in: Some(Duration::from_secs(300)),
    ..Default::default()
})?;

let value: Value = verifier.verify_json(&token, VerifyOptions {
    purpose: Some("login"),
    ..Default::default()
})?;
assert_eq!(value["user_id"], 42);
# Ok::<(), message_verifier::Error>(())
```

Signed payloads are readable by anyone. Use `Encryptor` for confidential data.

## Encrypt JSON

```rust
use message_verifier::{Encryptor, KeyGenerator, MessageOptions, VerifyOptions};
use serde_json::{json, Value};

// Matches Rails 7.0+ application key derivation defaults: SHA256, 1,000 iterations.
let key = KeyGenerator::rails("secret_key_base").generate_key("my encryption salt", 32)?;
let encryptor = Encryptor::new(key)?; // AES-256-GCM
let token = encryptor.encrypt_and_sign_json(&json!({"secret": "value"}), MessageOptions::default())?;
let value: Option<Value> = encryptor.decrypt_and_verify_json(&token, VerifyOptions::default())?;
assert_eq!(value.unwrap()["secret"], "value");
# Ok::<(), message_verifier::Error>(())
```

Encryption keys must have exactly `Cipher::key_len()` bytes. CBC supports a separate
`.signing_key(...)` and `.digest(...)`; GCM authenticates internally and ignores those settings.

## Compatibility and defaults

| Setting | This library's default | Rails / ActiveSupport compatibility |
| --- | --- | --- |
| Verifier digest | HMAC-SHA1 | Standalone ActiveSupport default; SHA256, SHA384, SHA512 configurable |
| Cipher | AES-256-GCM | Modern Rails application default; AES-CBC and AES-GCM at 128/192/256 bits supported |
| Encoding | Standard padded Base64 | `.encoding(Encoding::UrlSafe)` generates unpadded URL-safe tokens |
| JSON metadata | Current (`data` envelope) | Rails 7.1+ with JSON metadata enabled; reads legacy `message` envelopes too |
| `KeyGenerator::new` | SHA1, 65,536 iterations | Standalone ActiveSupport defaults |
| `KeyGenerator::rails` | SHA256, 1,000 iterations | Rails application defaults from 7.0 onward |

Rails defaults depend on the application's `config.load_defaults` and overrides.
Standalone ActiveSupport still defaults to Marshal serialization and, unless enabled,
CBC encryption and legacy metadata. Match the actual settings used by your application.

Verifier reads accept standard and URL-safe Base64 regardless of their generation setting.
Encryptor reads require the configured encoding; add a rotation to migrate encoding modes.

JSON methods serialize Rust values with Serde and enforce Rails metadata. Use
`.metadata_format(MetadataFormat::Legacy)` to generate Rails <= 7.0 envelopes or match
`force_legacy_metadata_serializer: true`. Expiration uses UTC millisecond ISO8601 timestamps;
`expires_at` takes precedence over `expires_in`, and a token is invalid at its expiration instant.
The expected purpose must match, including when one side has no purpose.
The `_rails` top-level JSON key is reserved for metadata, as it is in Rails.

This library implements JSON-compatible values, not Ruby Marshal, MessagePack, or
ActiveSupport-specific Ruby object extensions. Configure Ruby with `serializer: JSON`
or the JSON path of `serializer: :json`. Rails `:json_allow_marshal` tokens are supported
when their contents are JSON; its Marshal fallback is not implemented. JSON text may
differ in escaping or object ordering while remaining interoperable in both directions.

For matching current metadata in standalone Ruby:

```ruby
require 'active_support'
require 'active_support/message_verifier'
require 'json'
ActiveSupport::Messages::Metadata.use_message_serializer_for_metadata = true
verifier = ActiveSupport::MessageVerifier.new(
  'a signing secret', digest: 'SHA256', serializer: JSON, url_safe: true
)
```

### Raw serialized payloads

```rust
use message_verifier::Verifier;

let verifier = Verifier::new(b"binary or text signing key");
let token = verifier.generate(b"already serialized bytes");
assert_eq!(verifier.verify(&token)?, b"already serialized bytes");
# Ok::<(), message_verifier::Error>(())
```

`generate` / `verify` and `encrypt_and_sign` / `decrypt_and_verify` operate on raw bytes.
They do not interpret or enforce metadata inside those bytes. Use the JSON methods for
purpose/expiration checks. Raw operations match Rails with a `NullSerializer`, or can
carry caller-serialized JSON/Marshal/MessagePack without interpreting it.

### Failure semantics

| Method | Invalid token | Expired / wrong purpose | JSON deserialization error |
| --- | --- | --- | --- |
| `verify_json` | `Err(InvalidSignature)` | `Err(InvalidSignature)` | `Err(Serialization)` |
| `verified_json` | `Ok(None)` | `Ok(None)` | `Err(Serialization)` |
| `decrypt_and_verify_json` | `Err(InvalidMessage)` | `Ok(None)` | `Err(Serialization)` |

All JSON optional results use `Result<Option<T>>`; use `T = serde_json::Value` to
distinguish a valid JSON `null` (`Some(Value::Null)`) from a rejected token (`None`).
`valid_message` checks only the primary signature, without decoding or checking metadata.
`verified` is the optional raw verification method. `VerifyOptions::now` allows an explicit clock
for deterministic expiration checks.

### Rotation

```rust
use message_verifier::{Digest, Verifier};

let mut verifier = Verifier::builder("new secret").digest(Digest::Sha512).build();
verifier.rotate(Verifier::new("old secret"));
let old_token = Verifier::new("old secret").generate("payload");
assert_eq!(verifier.verify(&old_token)?, b"payload");
# Ok::<(), message_verifier::Error>(())
```

`Encryptor::rotate` accepts a fully configured fallback too, including a different cipher,
key, signing digest, or encoding. Fallback settings are explicit, not inherited.
Generation always uses the primary configuration. Reads try fallbacks in insertion order
on authentication, format, or serialization failures. Expired and purpose-mismatched
messages stop rotation immediately, matching Rails.

## Examples and development

```sh
cargo run --example metadata
cargo run --example generate_encrypt | cargo run --example verify_decrypt
cargo run --example generate_encrypt | ruby examples/verify_decrypt.rb
ruby examples/generate_encrypt.rb | cargo run --example verify_decrypt
cargo run --example aead_encrypt | ruby examples/aead_decrypt.rb
ruby examples/aead_encrypt.rb | cargo run --example aead_decrypt

cargo test --all-targets
cargo test --doc
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
# Live tests require Ruby and the activesupport gem. Static Rails fixtures run without Ruby.
cargo test --test rails -- --ignored
```

CI runs bidirectional tests against ActiveSupport 7.0, 7.2, and 8.1. Set
`ACTIVESUPPORT_VERSION` to select an installed gem version for local interoperability tests.
The ActiveSupport 7.x test matrix uses the JSON 2.x gem (`gem install json --version '~> 2.0'`).
The CBC and AEAD example pairs explicitly retain legacy SHA1/1,000-iteration key derivation.

See [MIGRATION.md](MIGRATION.md) for the 2.x → 3.0 API changes.

## Contributors

- [mjc-gh](https://github.com/mjc-gh/)
- [seanlinsley](https://github.com/seanlinsley)
- [endoze](https://github.com/endoze)
