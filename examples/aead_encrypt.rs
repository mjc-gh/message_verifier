use message_verifier::{Encryptor, KeyGenerator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = KeyGenerator::new("helloworld")
        .iterations(1000)
        .generate_key("test salt", 32)?;
    let encryptor = Encryptor::new(key)?;
    println!("{}", encryptor.encrypt_and_sign(r#"{"key":"value"}"#)?);
    Ok(())
}
