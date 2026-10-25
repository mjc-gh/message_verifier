use std::io::{self, Read};

use message_verifier::{Cipher, Encryptor, KeyGenerator, Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let generator = KeyGenerator::new("helloworld").iterations(1000);
    let encryptor = Encryptor::builder(generator.generate_key("test salt", 32)?)
        .cipher(Cipher::Aes256Cbc)
        .signing_key(generator.generate_key("test signed salt", 64)?)
        .build()?;
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let mut lines = input.lines();
    let signed = lines.next().ok_or("missing signed message")?;
    let encrypted = lines.next().ok_or("missing encrypted message")?;
    println!(
        "Verified Message: {}",
        String::from_utf8(Verifier::new("helloworld").verify(signed)?)?
    );
    println!(
        "Decrypted Message: {}",
        String::from_utf8(encryptor.decrypt_and_verify(encrypted)?)?
    );
    Ok(())
}
