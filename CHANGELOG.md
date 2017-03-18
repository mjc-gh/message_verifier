*Version 1.1.0*

- The `Encryptor` type is now a trait which is implemented by the
  `AesHmacEncryptor` and `AesGcmEncryptor` types.
- The `set_cipher` function has been renamed to `set_cipher_key_size`
  and the `EncryptorCipher` type has been renamed to `KeySize`.
