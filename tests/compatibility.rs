use std::time::{Duration, UNIX_EPOCH};

use message_verifier::{
    Cipher, Digest, Encoding, Encryptor, Error, KeyGenerator, MessageOptions, MetadataFormat,
    Verifier, VerifyOptions,
};
use serde_json::{json, Value};

const CIPHERS: [Cipher; 6] = [
    Cipher::Aes128Cbc,
    Cipher::Aes192Cbc,
    Cipher::Aes256Cbc,
    Cipher::Aes128Gcm,
    Cipher::Aes192Gcm,
    Cipher::Aes256Gcm,
];

#[test]
fn reads_checked_in_activesupport_8_1_fixtures_without_ruby() {
    let fixtures: Value = serde_json::from_str(include_str!("rails_fixtures.json")).unwrap();
    let options = VerifyOptions {
        purpose: Some("fixture"),
        now: Some(UNIX_EPOCH + Duration::from_secs(1_800_000_000)),
    };
    for fixture in fixtures["tokens"].as_array().unwrap() {
        let digest = match fixture["digest"].as_str().unwrap() {
            "SHA256" => Digest::Sha256,
            "SHA512" => Digest::Sha512,
            _ => Digest::Sha1,
        };
        let encoding = if fixture["url_safe"] == true {
            Encoding::UrlSafe
        } else {
            Encoding::Standard
        };
        let token = fixture["token"].as_str().unwrap();
        let value = if fixture["kind"] == "verifier" {
            Verifier::builder([0; 32])
                .digest(digest)
                .encoding(encoding)
                .build()
                .verify_json::<Value>(token, options)
                .unwrap()
        } else {
            let cipher = if fixture["cipher"] == "aes-256-cbc" {
                Cipher::Aes256Cbc
            } else {
                Cipher::Aes256Gcm
            };
            Encryptor::builder([0; 32])
                .cipher(cipher)
                .digest(digest)
                .encoding(encoding)
                .build()
                .unwrap()
                .decrypt_and_verify_json::<Value>(token, options)
                .unwrap()
                .unwrap()
        };
        assert_eq!(value, fixtures["value"]);
    }
}

#[test]
fn gcm_parses_an_openssl_nonce_containing_only_delimiter_characters() {
    // Ruby/OpenSSL fixture, nonce bytes [251,239,190] repeated four times.
    let token = "v46YwtFIljbhVOt2aIgcgak--------------------iy_lQb0MWPU5OtmlATmG0A";
    let encryptor = Encryptor::builder([0; 32])
        .encoding(Encoding::UrlSafe)
        .build()
        .unwrap();
    assert_eq!(
        encryptor.decrypt_and_verify(token).unwrap(),
        b"delimiter fixture"
    );
}

#[test]
fn reads_original_version_two_rails_vectors() {
    let generator = KeyGenerator::new("helloworld").iterations(1000);
    let verifier = Verifier::new("helloworld");
    let signed = "eyJrZXkiOiJ2YWx1ZSJ9--fa115453dbb4a28277b1ba07ef4c7437621f5d72";
    let payload = br#"{"key":"value"}"#;
    assert_eq!(verifier.verify(signed).unwrap(), payload);
    assert_eq!(verifier.generate(payload), signed);
    let vectors = [
        (Cipher::Aes256Cbc, "c20wSnp6Z1o1U2MyWDVjU3BPeWNNQT09LS1JOWNyR25LdDRpZUUvcmoxVTdoSTNRPT0=--a79c9522355e55bf8e4302c66d8bf5638f1a50ec"),
        (Cipher::Aes192Cbc, "RXFQajB4VzR3QytRQ0NpQXlGUFFTdz09LS0ycUZlcWFXNlRsb1phanMvcHlwVCtRPT0=--5d4739f859e1f730dc0ae7abfb21160c9f00dae6"),
        (Cipher::Aes256Gcm, "H9msESjs5e8I6utXGnk0--4UI1B/xoA1MIR3A3--DHpzaZ7LMhFsWXzEbLiOCA=="),
    ];
    for (cipher, token) in vectors {
        let encryptor = Encryptor::builder(
            generator
                .generate_key("test salt", cipher.key_len())
                .unwrap(),
        )
        .cipher(cipher)
        .signing_key(generator.generate_key("test signed salt", 64).unwrap())
        .build()
        .unwrap();
        assert_eq!(encryptor.decrypt_and_verify(token).unwrap(), payload);
    }
}

#[test]
fn raw_bytes_roundtrip_and_tampering_fails_for_every_cipher() {
    for cipher in CIPHERS {
        for encoding in [Encoding::Standard, Encoding::UrlSafe] {
            let encryptor = Encryptor::builder(vec![0; cipher.key_len()])
                .cipher(cipher)
                .digest(Digest::Sha512)
                .encoding(encoding)
                .build()
                .unwrap();
            for payload in [b"".as_slice(), b"\0\xff\xfe\x80", b"message"] {
                let mut token = encryptor.encrypt_and_sign(payload).unwrap();
                assert_eq!(encryptor.decrypt_and_verify(&token).unwrap(), payload);
                assert_ne!(token, encryptor.encrypt_and_sign(payload).unwrap());
                let replacement = if token.starts_with('A') { "B" } else { "A" };
                token.replace_range(..1, replacement);
                assert!(encryptor.decrypt_and_verify(&token).is_err());
            }
        }
    }
}

#[test]
fn url_safe_verifiers_accept_both_alphabets_and_embedded_separators() {
    let payload = [251, 239, 190, 255];
    for digest in [Digest::Sha1, Digest::Sha256, Digest::Sha384, Digest::Sha512] {
        let standard = Verifier::builder(b"\xff\0secret").digest(digest).build();
        let url_safe = Verifier::builder(b"\xff\0secret")
            .digest(digest)
            .encoding(Encoding::UrlSafe)
            .build();
        let token = url_safe.generate(payload);
        assert!(token.starts_with("----"));
        for reader in [&standard, &url_safe] {
            assert_eq!(reader.verify(&token).unwrap(), payload);
            assert_eq!(reader.verify(&standard.generate(payload)).unwrap(), payload);
        }
    }
}

#[test]
fn malformed_signatures_nonces_and_tags_never_panic() {
    let verifier = Verifier::new("secret");
    let gcm = Encryptor::new([0; 32]).unwrap();
    let cbc = Encryptor::builder([0; 32])
        .cipher(Cipher::Aes256Cbc)
        .build()
        .unwrap();
    for token in ["", "--", "a--a", "é--é--é", "🐈", "☃--☃--☃", "----"] {
        assert!(!verifier.valid_message(token));
        assert!(verifier.verify(token).is_err());
        assert!(gcm.decrypt_and_verify(token).is_err());
        assert!(cbc.decrypt_and_verify(token).is_err());
    }
    let valid = verifier.generate("payload");
    let (data, _) = valid.rsplit_once("--").unwrap();
    for length in 0..160 {
        let token = format!("{data}--{}", "a".repeat(length));
        assert!(!verifier.valid_message(&token));
        assert!(verifier.verify(&token).is_err());
    }
    assert!(!verifier.valid_message(&valid.to_uppercase()));
    for iv_len in 0..32 {
        for tag_len in 0..32 {
            use base64::{engine::general_purpose::STANDARD, Engine};
            let token = format!(
                "AA==--{}--{}",
                STANDARD.encode(vec![0; iv_len]),
                STANDARD.encode(vec![0; tag_len])
            );
            assert!(gcm.decrypt_and_verify(&token).is_err());
        }
    }
    let token = gcm.encrypt_and_sign("payload").unwrap();
    for index in 0..token.len() {
        assert!(gcm.decrypt_and_verify(&token[..index]).is_err());
    }
    // A valid CBC MAC does not make a malformed IV or ciphertext valid.
    assert!(cbc
        .decrypt_and_verify(&Verifier::new([0; 32]).generate("AA==--AA=="))
        .is_err());
}

#[test]
fn invalid_configuration_returns_typed_errors() {
    for cipher in CIPHERS {
        for length in [0, cipher.key_len() - 1, cipher.key_len() + 1, 64] {
            assert!(matches!(
                Encryptor::builder(vec![0; length]).cipher(cipher).build(),
                Err(Error::InvalidKeyLength { .. })
            ));
        }
    }
    assert!(matches!(
        KeyGenerator::new("secret")
            .iterations(0)
            .generate_key("salt", 32),
        Err(Error::InvalidKeyDerivation)
    ));
    assert!(matches!(
        KeyGenerator::new("secret").generate_key("salt", 0),
        Err(Error::InvalidKeyDerivation)
    ));
}

#[test]
fn purposes_expiration_and_both_json_envelopes_match_rails() {
    let expires_at = UNIX_EPOCH + Duration::from_millis(1_893_456_000_123);
    let payload = json!({"text":"<hello> & café 🐈\u{2028}", "nested":[null, false, 123]});
    for format in [MetadataFormat::Current, MetadataFormat::Legacy] {
        let verifier = Verifier::builder("secret").metadata_format(format).build();
        let encryptor = Encryptor::builder([0; 32])
            .metadata_format(format)
            .build()
            .unwrap();
        let options = MessageOptions {
            purpose: Some("login"),
            expires_at: Some(expires_at),
            expires_in: Some(Duration::ZERO),
        };
        let token = verifier.generate_json(&payload, options).unwrap();
        let encrypted = encryptor.encrypt_and_sign_json(&payload, options).unwrap();
        let envelope: Value = serde_json::from_slice(&verifier.verify(&token).unwrap()).unwrap();
        assert_eq!(envelope["_rails"]["exp"], "2030-01-01T00:00:00.123Z");
        let expected = VerifyOptions {
            purpose: Some("login"),
            now: Some(expires_at - Duration::from_millis(1)),
        };
        assert_eq!(
            verifier.verify_json::<Value>(&token, expected).unwrap(),
            payload
        );
        assert_eq!(
            encryptor
                .decrypt_and_verify_json::<Value>(&encrypted, expected)
                .unwrap(),
            Some(payload.clone())
        );
        for options in [
            VerifyOptions {
                purpose: None,
                ..expected
            },
            VerifyOptions {
                purpose: Some("shipping"),
                ..expected
            },
            VerifyOptions {
                now: Some(expires_at),
                ..expected
            },
            VerifyOptions {
                now: Some(expires_at + Duration::from_secs(1)),
                ..expected
            },
        ] {
            assert!(matches!(
                verifier.verify_json::<Value>(&token, options),
                Err(Error::InvalidSignature)
            ));
            assert!(verifier
                .verified_json::<Value>(&token, options)
                .unwrap()
                .is_none());
            assert!(encryptor
                .decrypt_and_verify_json::<Value>(&encrypted, options)
                .unwrap()
                .is_none());
        }
        assert!(verifier.valid_message(&token)); // Does not check metadata.
        let unscoped = verifier
            .generate_json(&payload, MessageOptions::default())
            .unwrap();
        assert!(verifier
            .verified_json::<Value>(&unscoped, expected)
            .unwrap()
            .is_none());
        assert_eq!(
            verifier
                .verify_json::<Value>(&unscoped, VerifyOptions::default())
                .unwrap(),
            payload
        );
    }
}

#[test]
fn relative_expiration_and_legacy_null_fields() {
    let verifier = Verifier::builder("secret")
        .metadata_format(MetadataFormat::Legacy)
        .build();
    let token = verifier
        .generate_json(
            &true,
            MessageOptions {
                purpose: Some(""),
                ..Default::default()
            },
        )
        .unwrap();
    let envelope: Value = serde_json::from_slice(&verifier.verify(&token).unwrap()).unwrap();
    assert!(envelope["_rails"]["exp"].is_null());
    assert!(verifier
        .verify_json::<bool>(&token, VerifyOptions::default())
        .unwrap());
    let token = verifier
        .generate_json(
            &true,
            MessageOptions {
                expires_in: Some(Duration::ZERO),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(verifier
        .verified_json::<bool>(&token, VerifyOptions::default())
        .unwrap()
        .is_none());
    let token = verifier
        .generate_json(
            &true,
            MessageOptions {
                expires_in: Some(Duration::from_secs(3600)),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(verifier
        .verify_json::<bool>(&token, VerifyOptions::default())
        .unwrap());
    let envelope: Value = serde_json::from_slice(&verifier.verify(&token).unwrap()).unwrap();
    assert!(envelope["_rails"]["pur"].is_null());
    let impossible = UNIX_EPOCH.checked_add(Duration::from_secs(1_000_000_000_000));
    if let Some(expires_at) = impossible {
        assert!(matches!(
            verifier.generate_json(
                &true,
                MessageOptions {
                    expires_at: Some(expires_at),
                    ..Default::default()
                }
            ),
            Err(Error::InvalidTimestamp)
        ));
    }
}

#[test]
fn serialization_errors_are_distinct_from_rejected_messages() {
    let verifier = Verifier::new("secret");
    assert!(matches!(
        verifier.verified_json::<Value>(&verifier.generate("not JSON"), VerifyOptions::default()),
        Err(Error::Serialization(_))
    ));
    assert!(verifier
        .verified_json::<Value>("bad token", VerifyOptions::default())
        .unwrap()
        .is_none());
    for malformed in [
        r#"{"_rails":{"message":"truncated"#,
        r#"{"_rails":null}"#,
        r#"{"_rails":{"exp":"not a time","data":true}}"#,
        r#"{"_rails":{"message":"%%%","exp":null,"pur":null}}"#,
    ] {
        assert!(verifier
            .verified_json::<Value>(&verifier.generate(malformed), VerifyOptions::default())
            .unwrap()
            .is_none());
    }
    let encryptor = Encryptor::new([0; 32]).unwrap();
    assert!(matches!(
        encryptor.decrypt_and_verify_json::<Value>("bad token", VerifyOptions::default()),
        Err(Error::InvalidMessage)
    ));
}

#[test]
fn rotations_migrate_keys_digests_ciphers_and_encoding_but_only_write_primary() {
    let old = Verifier::builder("old").digest(Digest::Sha1).build();
    let token = old
        .generate_json(&json!({"id":42}), MessageOptions::default())
        .unwrap();
    let mut current = Verifier::builder("new")
        .digest(Digest::Sha512)
        .encoding(Encoding::UrlSafe)
        .build();
    assert!(current.verify(&token).is_err());
    current.rotate(old.clone());
    assert_eq!(
        current
            .verify_json::<Value>(&token, VerifyOptions::default())
            .unwrap(),
        json!({"id":42})
    );
    assert!(old.verify(&current.generate("new data")).is_err());
    let old = Encryptor::builder([1; 16])
        .cipher(Cipher::Aes128Cbc)
        .digest(Digest::Sha256)
        .metadata_format(MetadataFormat::Legacy)
        .build()
        .unwrap();
    let token = old
        .encrypt_and_sign_json(
            &42,
            MessageOptions {
                purpose: Some("login"),
                ..Default::default()
            },
        )
        .unwrap();
    let mut current = Encryptor::builder([2; 32])
        .encoding(Encoding::UrlSafe)
        .build()
        .unwrap();
    assert!(current.decrypt_and_verify(&token).is_err());
    current.rotate(old.clone());
    assert_eq!(
        current
            .decrypt_and_verify_json::<u32>(
                &token,
                VerifyOptions {
                    purpose: Some("login"),
                    ..Default::default()
                }
            )
            .unwrap(),
        Some(42)
    );
    assert!(current
        .decrypt_and_verify_json::<u32>(&token, VerifyOptions::default())
        .unwrap()
        .is_none());
    assert!(old
        .decrypt_and_verify(&current.encrypt_and_sign("new data").unwrap())
        .is_err());
}
