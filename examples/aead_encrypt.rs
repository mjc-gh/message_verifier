extern crate message_verifier;

use message_verifier::{AesGcmEncryptor, DerivedKeyParams, Encryptor};

fn main() {
    let key_base = "helloworld";
    let salt = "test salt";

    let dkp = DerivedKeyParams::default();
    let encryptor = AesGcmEncryptor::new(key_base, salt, dkp).unwrap();

    let message = "{\"key\":\"value\"}";

    println!(
        "{}",
        encryptor
            .encrypt_and_sign(message)
            .expect("Encryptor failed")
    );
}
