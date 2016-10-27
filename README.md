# message_verifier

Message Verifier library compatible with Rails' [MessageVerifier](
http://api.rubyonrails.org/classes/ActiveSupport/MessageVerifier.html)
and
[MessageEncryptor](
http://api.rubyonrails.org/classes/ActiveSupport/MessageEncryptor.html).

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
message_verifier = "0.1"
```

## Example

Currently only decryption and verification are supported. Encryption and
signing will be implemented soon.

There is a small ruby script to generate encrypted and signed message.
It can be run as so:

    $ ruby examples/generate_encrypt.rb
    eyJrZXkiOiJ2YWx1ZSJ9--fa115453dbb4a28277b1ba07ef4c7437621f5d72
    M25lU1FzNlBUZjBxQTB2UHppVERxdz09LS1kanhScSs1L1ZRcFdXQk14WEYyOTBnPT0=--408ed6ffca4e0344d1066573ab9652fea7c462ce

This output can be piped to the Rust example to show how messages are
verified and decrypted:

    $ ruby examples/generate_encrypt.rb | cargo run --example verify_decrypt
    Verified Message: {"key":"value"}
    Decrypted Message: {"key":"value"}
