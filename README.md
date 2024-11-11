# message_verifier

[![message_verifier](https://github.com/mjc-gh/message_verifier/actions/workflows/actions.yml/badge.svg)](https://github.com/mjc-gh/message_verifier/actions/workflows/actions.yml)
[![Crates.io Version](https://img.shields.io/crates/v/message_verifier)](https://crates.io/crates/message_verifier)
[![MIT Licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE.md)

Message Verifier library compatible with Rails' [MessageVerifier](
http://api.rubyonrails.org/classes/ActiveSupport/MessageVerifier.html)
and
[MessageEncryptor](
http://api.rubyonrails.org/classes/ActiveSupport/MessageEncryptor.html).

In a nutshell, this library provides several simple interfaces for
signing and encrypting messages. These interfaces are useful when
securely implementing various web application features like session
cookies or signed URL tokens.

This library handles all the formatting, encoding, and cryptography. It
does not handle serialization aspects. The idea is to input and output
raw strings to and from this library and handle serialization on another
layer.

### Documentation

Documentation is available on [Docs.rs](https://docs.rs/message_verifier).


### A Small Example

```
 extern crate message_verifier;

 use message_verifier::{Verifier, Encryptor, AesHmacEncryptor, DerivedKeyParams};

 fn main() {
     let key_base = "helloworld";
     let salt = "test salt";
     let sign_salt = "test signed salt";

     let verifier = Verifier::new(key_base);

     //let dkp = DerivedKeyParams::default();
     //let encryptor = AesHmacEncryptor::new(key_base, salt, sign_salt, dkp).unwrap();

     let message = "{\"key\":\"value\"}";

     println!("{}", verifier.generate(message).expect("Verifier failed"));
     //println!("{}", encryptor.encrypt_and_sign(message).expect("Encryptor failed"));
 }
```

### More Examples

The examples directory contains two Rust examples as well as two small
Ruby scripts to demonstrate interoperability between this library and
ActiveSupport.

One Rust example demonstrates message signing and encryption:

```sh
$ cargo run --example generate_encrypt
eyJrZXkiOiJ2YWx1ZSJ9--fa115453dbb4a28277b1ba07ef4c7437621f5d72
MllIRUYvUFhjcXBpRk9NUWgvZ2s2UT09LS1NRmN2b2Y5SWJsaUpRNlptZFdwSlZRPT0=--2df97d947a5dc344de003715510002503fa059f1
```

The second reads from stdin and tries verify the first line of input and
decrypt and verify the second:

```sh
$ cargo run --example generate_encrypt | cargo run --example verify_decrypt
Verified Message: {"key":"value"}
Decrypted Message: {"key":"value"}
```

We can use these two Rust examples with the Ruby scripts as well:

```sh
$ cargo run --example generate_encrypt | ruby examples/verify_decrypt.rb
Verified message: {"key"=>"value"}
Decrypted message: {"key"=>"value"}

$ ruby examples/generate_encrypt.rb | cargo run --example verify_decrypt
Verified Message: {"key":"value"}
Decrypted Message: {"key":"value"}
```

### Supported Ciphers

- AES-CBC with HMAC-SHA1
  - 256, 192, or 128 bit keys
- AES-GCM
  - 256, 192, or 128 bit keys

If you need more cipher options, please open an issue or submit a PR!

## Contributors

- [mjc-gh](https://github.com/mjc-gh/)
- [seanlinsley](https://github.com/seanlinsley)
- [endoze](https://github.com/endoze)
