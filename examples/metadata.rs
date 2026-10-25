use std::time::Duration;

use message_verifier::{Digest, Encoding, MessageOptions, Verifier, VerifyOptions};
use serde_json::{json, Value};

fn main() -> message_verifier::Result<()> {
    let mut verifier = Verifier::builder("current signing secret")
        .digest(Digest::Sha256)
        .encoding(Encoding::UrlSafe)
        .build();
    verifier.rotate(Verifier::new("previous signing secret"));
    let token = verifier.generate_json(
        &json!({"user_id": 42}),
        MessageOptions {
            purpose: Some("login"),
            expires_in: Some(Duration::from_secs(300)),
            ..Default::default()
        },
    )?;
    println!("Token: {token}");
    let value: Value = verifier.verify_json(
        &token,
        VerifyOptions {
            purpose: Some("login"),
            ..Default::default()
        },
    )?;
    println!("Verified: {value}");
    Ok(())
}
