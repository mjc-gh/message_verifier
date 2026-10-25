//! Opt-in live interoperability: cargo test --test rails -- --ignored
use std::{
    io::Write,
    process::{Command, Stdio},
    time::{Duration, UNIX_EPOCH},
};

use message_verifier::{
    Cipher, Digest, Encoding, Encryptor, KeyGenerator, MessageOptions, MetadataFormat, Verifier,
    VerifyOptions,
};
use serde_json::{json, Value};

fn ruby(requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new("ruby")
        .arg(format!(
            "{}/tests/rails_interop.rb",
            env!("CARGO_MANIFEST_DIR")
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Ruby must be available for live Rails interoperability tests");
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(&serde_json::to_vec(requests).unwrap())
        .unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "Ruby interoperability process failed"
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
#[ignore = "requires Ruby and the activesupport gem; run with --ignored"]
fn bidirectional_rails_json_and_raw_tokens() {
    let version = std::env::var("ACTIVESUPPORT_VERSION").unwrap_or_default();
    let legacy_only = version.starts_with("7.0");
    let payload =
        json!({"text":"<hello> & café 🐈\u{2028}\u{2029}", "array":[true, false, null, 42, 1.25]});
    let ciphers = [
        (Cipher::Aes128Cbc, "aes-128-cbc"),
        (Cipher::Aes192Cbc, "aes-192-cbc"),
        (Cipher::Aes256Cbc, "aes-256-cbc"),
        (Cipher::Aes128Gcm, "aes-128-gcm"),
        (Cipher::Aes192Gcm, "aes-192-gcm"),
        (Cipher::Aes256Gcm, "aes-256-gcm"),
    ];
    let mut requests = Vec::new();
    let mut configs = Vec::new();
    for (digest, name) in [
        (Digest::Sha1, "SHA1"),
        (Digest::Sha256, "SHA256"),
        (Digest::Sha384, "SHA384"),
        (Digest::Sha512, "SHA512"),
    ] {
        for encoding in [Encoding::Standard, Encoding::UrlSafe] {
            if legacy_only && encoding == Encoding::UrlSafe {
                continue;
            }
            for metadata in [MetadataFormat::Legacy, MetadataFormat::Current] {
                if legacy_only && metadata == MetadataFormat::Current {
                    continue;
                }
                for kind in 0..=ciphers.len() {
                    let mut request = json!({"op":"generate", "digest":name,
                        "url_safe": encoding == Encoding::UrlSafe,
                        "legacy":metadata == MetadataFormat::Legacy, "purpose":"login",
                        "expires_at":"2030-01-01T00:00:00.123Z", "value":payload});
                    if kind == 0 {
                        request["kind"] = json!("verifier");
                        request["key"] = json!(hex::encode(b"\0\xffsigning secret"));
                    } else {
                        let (cipher, name) = ciphers[kind - 1];
                        request["kind"] = json!("encryptor");
                        request["cipher"] = json!(name);
                        request["key"] =
                            json!(hex::encode((0..cipher.key_len() as u8).collect::<Vec<_>>()));
                        request["signing_key"] = json!(hex::encode(b"\xff\0separate signing key"));
                    }
                    requests.push(request);
                    configs.push((digest, encoding, metadata, kind));
                }
            }
        }
    }
    let tokens = ruby(&requests);
    let mut read_requests = Vec::new();
    let options = MessageOptions {
        purpose: Some("login"),
        expires_at: Some(UNIX_EPOCH + Duration::from_millis(1_893_456_000_123)),
        ..Default::default()
    };
    let expired = MessageOptions {
        expires_at: Some(UNIX_EPOCH),
        ..options
    };
    for ((request, token), &(digest, encoding, metadata, kind)) in
        requests.iter().zip(tokens).zip(&configs)
    {
        let token = token.as_str().unwrap();
        let key = hex::decode(request["key"].as_str().unwrap()).unwrap();
        let expected = VerifyOptions {
            purpose: Some("login"),
            ..Default::default()
        };
        let (rust_token, expired_token) = if kind == 0 {
            let verifier = Verifier::builder(key)
                .digest(digest)
                .encoding(encoding)
                .metadata_format(metadata)
                .build();
            assert_eq!(
                verifier.verify_json::<Value>(token, expected).unwrap(),
                payload
            );
            assert!(verifier
                .verified_json::<Value>(token, VerifyOptions::default())
                .unwrap()
                .is_none());
            (
                verifier.generate_json(&payload, options).unwrap(),
                verifier.generate_json(&payload, expired).unwrap(),
            )
        } else {
            let encryptor = Encryptor::builder(key)
                .cipher(ciphers[kind - 1].0)
                .digest(digest)
                .encoding(encoding)
                .metadata_format(metadata)
                .signing_key(b"\xff\0separate signing key")
                .build()
                .unwrap();
            assert_eq!(
                encryptor
                    .decrypt_and_verify_json::<Value>(token, expected)
                    .unwrap(),
                Some(payload.clone())
            );
            assert!(encryptor
                .decrypt_and_verify_json::<Value>(token, VerifyOptions::default())
                .unwrap()
                .is_none());
            (
                encryptor.encrypt_and_sign_json(&payload, options).unwrap(),
                encryptor.encrypt_and_sign_json(&payload, expired).unwrap(),
            )
        };
        let mut read = request.clone();
        read["op"] = json!("read");
        read["token"] = json!(rust_token);
        read_requests.push(read.clone());
        read["purpose"] = json!("shipping");
        read_requests.push(read.clone());
        read["purpose"] = json!("login");
        read["token"] = json!(expired_token);
        read_requests.push(read);
    }
    for result in ruby(&read_requests).chunks_exact(3) {
        assert_eq!(result[0], payload);
        assert_eq!(result[1], Value::Null);
        assert_eq!(result[2], Value::Null);
    }

    // Raw binary payloads roundtrip with Rails' NullSerializer, including URL-safe `--`.
    let verifier = Verifier::builder(b"\0\xffsecret")
        .encoding(Encoding::UrlSafe)
        .build();
    let mut request = json!({"op":"read", "kind":"verifier", "raw":true,
        "key":hex::encode(b"\0\xffsecret"), "url_safe":true,
        "token":verifier.generate([251, 239, 190, 255])});
    if !legacy_only {
        assert_eq!(ruby(&[request.clone()])[0], "fbefbeff");
        request["op"] = json!("generate");
        request["value"] = json!("fbefbeff");
        assert_eq!(
            verifier
                .verify(ruby(&[request])[0].as_str().unwrap())
                .unwrap(),
            [251, 239, 190, 255]
        );
    }
}

#[test]
#[ignore = "requires Ruby and the activesupport gem; run with --ignored"]
fn binary_payloads_roundtrip_for_every_cipher() {
    let legacy_only = std::env::var("ACTIVESUPPORT_VERSION")
        .unwrap_or_default()
        .starts_with("7.0");
    let ciphers = [
        (Cipher::Aes128Cbc, "aes-128-cbc"),
        (Cipher::Aes192Cbc, "aes-192-cbc"),
        (Cipher::Aes256Cbc, "aes-256-cbc"),
        (Cipher::Aes128Gcm, "aes-128-gcm"),
        (Cipher::Aes192Gcm, "aes-192-gcm"),
        (Cipher::Aes256Gcm, "aes-256-gcm"),
    ];
    let payload = [0, 255, 251, 239, 190, 128];
    let mut generate = Vec::new();
    let mut read = Vec::new();
    let mut encryptors = Vec::new();
    for (cipher, name) in ciphers {
        for encoding in [Encoding::Standard, Encoding::UrlSafe] {
            if legacy_only && encoding == Encoding::UrlSafe {
                continue;
            }
            let key = vec![0; cipher.key_len()];
            let encryptor = Encryptor::builder(&key)
                .cipher(cipher)
                .encoding(encoding)
                .build()
                .unwrap();
            let mut request = json!({"op":"generate", "kind":"encryptor", "raw":true,
                "key":hex::encode(key), "cipher":name, "url_safe":encoding == Encoding::UrlSafe,
                "value":hex::encode(payload)});
            generate.push(request.clone());
            request["op"] = json!("read");
            request["token"] = json!(encryptor.encrypt_and_sign(payload).unwrap());
            read.push(request);
            encryptors.push(encryptor);
        }
    }
    for (encryptor, token) in encryptors.iter().zip(ruby(&generate)) {
        assert_eq!(
            encryptor
                .decrypt_and_verify(token.as_str().unwrap())
                .unwrap(),
            payload
        );
    }
    for result in ruby(&read) {
        assert_eq!(result, hex::encode(payload));
    }
}

#[test]
#[ignore = "requires Ruby and the activesupport gem; run with --ignored"]
fn pbkdf2_matches_ruby_for_all_digests_and_binary_inputs() {
    let mut requests = Vec::new();
    let mut expected = Vec::new();
    for (digest, name) in [
        (Digest::Sha1, "SHA1"),
        (Digest::Sha256, "SHA256"),
        (Digest::Sha384, "SHA384"),
        (Digest::Sha512, "SHA512"),
    ] {
        for iterations in [1, 1000, 65_536] {
            for length in [16, 24, 32, 64] {
                requests.push(
                    json!({"op":"derive", "key":"ff00736563726574", "salt":"00ff73616c74",
                    "digest":name, "iterations":iterations, "length":length}),
                );
                expected.push(json!(hex::encode(
                    KeyGenerator::new(b"\xff\0secret")
                        .digest(digest)
                        .iterations(iterations)
                        .generate_key(b"\0\xffsalt", length)
                        .unwrap()
                )));
            }
        }
    }
    assert_eq!(ruby(&requests), expected);
}
