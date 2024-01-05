*Version 2.0.0*

- Dependency updates from
  [@seanlinsley](https://github.com/seanlinsley). This package now uses
  more modern cryptographic crates from the
  [@RustCrypto](https://github.com/RustCrypto).
  - The `set_cipher_key_size` function was removed, instead just set the
    encryptor's `key_size` property directly:
    `e.key_size = KeySize::Aes256`
  - `Verifier#generate` now returns a `Result<String>`

*Version 1.1.0*

- The `Encryptor` type is now a trait which is implemented by the
  `AesHmacEncryptor` and `AesGcmEncryptor` types.
- The `set_cipher` function has been renamed to `set_cipher_key_size`
  and the `EncryptorCipher` type has been renamed to `KeySize`.
