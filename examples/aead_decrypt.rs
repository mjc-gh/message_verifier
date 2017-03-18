
extern crate message_verifier;

use message_verifier::{Encryptor, AesGcmEncryptor, DerivedKeyParams};

use std::io;
use std::io::Read;
use std::str;

fn main() {
    let key_base = "helloworld";
    let salt = "test salt";

    let dkp = DerivedKeyParams::default();
    let encryptor = AesGcmEncryptor::new(key_base, salt, dkp).unwrap();

    let mut message = String::new();

    match io::stdin().read_to_string(&mut message) {
        Err(_) => panic!("Read failed"),
        Ok(_) => {
            match encryptor.decrypt_and_verify(&message.trim()) {
                Ok(ref decrypted_result) => {
                    println!("Decrypted Message: {}", str::from_utf8(&decrypted_result).expect("Encryptor failed"));
                }

                Err(e) => panic!("Encryptor Error: {:?}", e)
            }
        }
    }
}
