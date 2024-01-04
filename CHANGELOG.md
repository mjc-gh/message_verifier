*Version 2.0.0*

- Dependency updates from
  [@seanlinsley](https://github.com/seanlinsley). This package now uses
  more modern cryptographic crates from the
  [@RustCrypto](https://github.com/RustCrypto).

*Version 1.1.0*

- The `Encryptor` type is now a trait which is implemented by the
  `AesHmacEncryptor` and `AesGcmEncryptor` types.
- The `set_cipher` function has been renamed to `set_cipher_key_size`
  and the `EncryptorCipher` type has been renamed to `KeySize`.
