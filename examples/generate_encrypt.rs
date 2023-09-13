extern crate message_verifier;

use message_verifier::{AesHmacEncryptor, DerivedKeyParams, Encryptor, Verifier};

fn main() {
    let key_base = "helloworld";
    let salt = "test salt";
    let sign_salt = "test signed salt";

    let verifier = Verifier::new(key_base);

    let dkp = DerivedKeyParams::default();
    let encryptor = AesHmacEncryptor::new(key_base, salt, sign_salt, dkp).unwrap();

    let message = "{\"key\":\"value\"}";

    println!("{}", verifier.generate(message).expect("Verifier failed"));
    println!(
        "{}",
        encryptor
            .encrypt_and_sign(message)
            .expect("Encryptor failed")
    );
}
