use message_verifier::{Cipher, Encryptor, KeyGenerator, Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Explicit legacy settings preserve interoperability with the original examples.
    let generator = KeyGenerator::new("helloworld").iterations(1000);
    let encryptor = Encryptor::builder(generator.generate_key("test salt", 32)?)
        .cipher(Cipher::Aes256Cbc)
        .signing_key(generator.generate_key("test signed salt", 64)?)
        .build()?;
    let message = r#"{"key":"value"}"#;
    println!("{}", Verifier::new("helloworld").generate(message));
    println!("{}", encryptor.encrypt_and_sign(message)?);
    Ok(())
}
