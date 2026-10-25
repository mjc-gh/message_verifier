use std::io::{self, Read};

use message_verifier::{Encryptor, KeyGenerator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = KeyGenerator::new("helloworld")
        .iterations(1000)
        .generate_key("test salt", 32)?;
    let encryptor = Encryptor::new(key)?;
    let mut token = String::new();
    io::stdin().read_to_string(&mut token)?;
    println!(
        "Decrypted Message: {}",
        String::from_utf8(encryptor.decrypt_and_verify(token.trim())?)?
    );
    Ok(())
}
