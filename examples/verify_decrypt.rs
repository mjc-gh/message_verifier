extern crate message_verifier;

use message_verifier::{Verifier, Encryptor};

use std::io;
use std::str;

fn main() {
    let key_base = "helloworld";
    let salt = "test salt";
    let sign_salt = "test signed salt";

    let verifier = Verifier::new(key_base);
    let encryptor = Encryptor::new(key_base, salt, sign_salt, 1000, 64).unwrap();

    let mut input: Vec<String> = vec![];
    let mut buffer = String::new();

    for _ in 0..2 {
        match io::stdin().read_line(&mut buffer) {
            Ok(_) => {
                input.push(buffer.clone());

                buffer.clear();
            }

            Err(_) => panic!("Read failed")
        }
    }

    let (msg1, msg2) = match (input.first(), input.last()) {
        (Some(m1), Some(m2)) => (m1, m2),

        _ => panic!("Missing input")
    };

    match verifier.verify(&msg1) {
        Ok(verified_result) => {
            match encryptor.decrypt_and_verify(&msg2) {
                Ok(decrypted_result) => {
                    println!("Verified Message: {}", str::from_utf8(&verified_result).unwrap());
                    println!("Decrypted Message: {}", str::from_utf8(&decrypted_result).unwrap());
                }

                Err(e) => panic!("Encryptor Error: {:?}", e)
            }
        }

        Err(e) => panic!("Verifier Error: {:?}", e)
    }
}
