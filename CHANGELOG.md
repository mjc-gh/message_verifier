*Version 3.0.0*

- Redesign configuration around `Verifier` and `Encryptor` builders, binary keys,
  immutable cipher selection, and separate `KeyGenerator` PBKDF2 derivation.
- Add SHA256/SHA384/SHA512 signing and key derivation, unpadded URL-safe Base64,
  Rails legacy/current JSON envelopes, purpose checks, expiration, and rotation.
- Add strict/optional JSON APIs and typed errors; retain raw serialized payload APIs.
- Reject malformed signatures, nonces, tags, and undersized keys without panicking;
  parse URL-safe tokens containing `--` using fixed-length fields.
- Update RustCrypto dependencies, declare Rust 1.89 MSRV, and modernize CI.
- Add checked-in Rails fixtures and bidirectional ActiveSupport interoperability tests.
- See [MIGRATION.md](MIGRATION.md) for breaking API changes and legacy key settings.

*Version 2.0.0*

- Dependency updates from
  [@seanlinsley](https://github.com/seanlinsley). This package now uses
  more modern cryptographic crates from the
  [@RustCrypto](https://github.com/RustCrypto) team.
  - The `set_cipher_key_size` function was removed, instead just set the
    encryptor's `key_size` property directly:
    `e.key_size = KeySize::Aes256`
  - `Verifier#generate` now returns a `Result<String>`

*Version 1.1.0*

- The `Encryptor` type is now a trait which is implemented by the
  `AesHmacEncryptor` and `AesGcmEncryptor` types.
- The `set_cipher` function has been renamed to `set_cipher_key_size`
  and the `EncryptorCipher` type has been renamed to `KeySize`.
