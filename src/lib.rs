//! Message Verifier library compatible with Rails'
//! [MessageVerifier](http://api.rubyonrails.org/classes/ActiveSupport/MessageVerifier.html) and
//! [MessageEncryptor](http://api.rubyonrails.org/classes/ActiveSupport/MessageEncryptor.html).
//!
//! #### A Small Example
//!
//! Please refer to the
//! [README](https://github.com/mikeycgto/message_verifier/blob/master/README.md)
//! and [repo](https://github.com/mikeycgto/message_verifier) for more examples.
//!
//! ```
//!  extern crate message_verifier;
//!
//!  use message_verifier::{Verifier, Encryptor, AesHmacEncryptor, DerivedKeyParams};
//!
//!  fn main() {
//!      let key_base = "helloworld";
//!      let salt = "test salt";
//!      let sign_salt = "test signed salt";
//!
//!      let verifier = Verifier::new(key_base);
//!
//!      //let dkp = DerivedKeyParams::default();
//!      //let encryptor = AesHmacEncryptor::new(key_base, salt, sign_salt, dkp).unwrap();
//!
//!      let message = "{\"key\":\"value\"}";
//!
//!      println!("{}", verifier.generate(message));
//!      //println!("{}", encryptor.encrypt_and_sign(message).expect("Encryptor failed"));
//!  }
//! ```

extern crate crypto;
extern crate rand;
extern crate rustc_serialize;

#[macro_use]
extern crate error_chain;

use crypto::{buffer, blockmodes};
use crypto::aes::{cbc_decryptor, cbc_encryptor, KeySize as AesKeySize};
use crypto::aes_gcm::AesGcm;
use crypto::aead::{AeadEncryptor, AeadDecryptor};
use crypto::buffer::{WriteBuffer, ReadBuffer, BufferResult};
use crypto::hmac::Hmac;
use crypto::mac::{Mac};
use crypto::sha1::Sha1;
use crypto::pbkdf2::pbkdf2;
use crypto::util::fixed_time_eq;

use rand::{Rng, OsRng};

use rustc_serialize::hex::{FromHex, ToHex};
use rustc_serialize::base64::{FromBase64, FromBase64Error, ToBase64, STANDARD};

use std::str::from_utf8;

error_chain! {
    foreign_links {
        DecodeBase64(FromBase64Error);
    }

    errors {
        InvalidSignature {
            description("Invalid message signature")
        }

        InvalidMessage {
            description("Invalid message encoding or format")
        }

        KeyDerivationFailure {
            description("Key Derivation Function failed to generate one or more keys")
        }

        RandomGeneratorFailure {
            description("OsRng failed to generate random bytes")
        }
    }
}

/// Verifier struct; similiar to ActiveSupport::MessageVerifier.
pub struct Verifier {
    secret_key: Vec<u8>
}

/// Encryption cipher key options. Only AES with 256, 192 or 128 bits is supported.
pub enum KeySize {
    Aes128,
    Aes192,
    Aes256
}

impl From<KeySize> for AesKeySize {
    fn from(cipher: KeySize) -> AesKeySize {
        match cipher {
            KeySize::Aes128 => AesKeySize::KeySize128,
            KeySize::Aes192 => AesKeySize::KeySize192,
            KeySize::Aes256 => AesKeySize::KeySize256
        }
    }
}

/// Encryptor trait; similiar to ActiveSupport::MessageEncryptor. Implemented by AesHmacEncryptor
/// and AesGcmEncryptor.
pub trait Encryptor {
    fn decrypt_and_verify(&self, &str) -> Result<Vec<u8>>;
    fn encrypt_and_sign(&self, &str) -> Result<String>;
}

/// AesHmacEncryptor struct; similiar to ActiveSupport::MessageEncryptor
pub struct AesHmacEncryptor {
    key_size: AesKeySize,
    secret_key: Vec<u8>,
    verifier: Verifier
}

/// AesGcmEncryptor struct; similiar to ActiveSupport::MessageEncryptor
pub struct AesGcmEncryptor {
    key_size: AesKeySize,
    secret_key: Vec<u8>,
}

/// Key derivation parameters for PBKDF2 function.
pub struct DerivedKeyParams {
    size: u32,
    iterations: u32
}

impl Default for DerivedKeyParams {
    /// The default mimics Rails' secure cookie setup which is
    /// 64 bytes (512 bits) for the key size and 1000 iterations.
    ///
    /// ActiveSupport::KeyGenerator will default to 2^16 (65536) iterations.
    fn default() -> DerivedKeyParams {
        DerivedKeyParams { size: 64, iterations: 1000 }
    }
}

/// Create one or more PBKDF2 derived keys using a secret, some key parameters
/// and one or more salts.
pub fn create_derived_keys(salts: &Vec<&str>, secret: &str, key_params: DerivedKeyParams) -> Vec<Vec<u8>> {
    let mut mac = Hmac::new(Sha1::new(), secret.as_bytes());

    salts.iter().map(|salt| {
        let mut result: Vec<u8> = vec![0; key_params.size as usize];

        pbkdf2(&mut mac, salt.as_bytes(), key_params.iterations, &mut result);

        result
    }).collect()
}

fn random_iv(sz: usize) -> Result<Vec<u8>> {
    match OsRng::new() {
        Ok(mut rng) => {
            let mut buffer: Vec<u8> = vec![0; sz];

            rng.fill_bytes(&mut buffer);

            Ok(buffer)
        }

        Err(_) => bail!(ErrorKind::RandomGeneratorFailure)
    }
}

fn split_by_n_dashes(n: usize, message: &str) -> Result<Vec<&str>> {
    let split: Vec<&str> = message.splitn(n, "--").collect();

    if split.len() == n {
        Ok(split)
    } else {
        bail!(ErrorKind::InvalidMessage)
    }
}

fn split_by_n_dashes_from_u8_slice(n: usize, slice: &[u8]) -> Result<Vec<&str>> {
    match from_utf8(slice) {
        Ok(string) => split_by_n_dashes(n, string),
        Err(_) => bail!(ErrorKind::InvalidMessage)
    }
}

impl Verifier {
    /// Create a new Verifier object.
    pub fn new(secret: &str) -> Verifier {
        Verifier {
            secret_key: secret.bytes().collect()
        }
    }

    /// Verify a signed message generated by a compatible verifier.
    pub fn verify(&self, message: &str) -> Result<Vec<u8>> {
        let msg_split = split_by_n_dashes(2, &message)?;

        let encoded_data = msg_split[0];
        let signature = msg_split[1];

        match self.is_valid_message(encoded_data, signature) {
            true  => Ok(encoded_data.from_base64()?),
            false => bail!(ErrorKind::InvalidSignature)
        }
    }

    /// Check if the given signature is valid for some encoded data.
    pub fn is_valid_message(&self, encoded_data: &str, signature: &str) -> bool {
        match signature.from_hex() {
            Ok(sig_bytes) => {
                let mut mac = Hmac::new(Sha1::new(), &self.secret_key);

                mac.input(encoded_data.as_bytes());

                fixed_time_eq(mac.result().code(), &sig_bytes)
            },

            Err(_) => false
        }
    }

    /// Generate a signed message from the input message. This message can
    /// be consumed and verified by a compatible verifier.
    pub fn generate(&self, message: &str) -> String {
        let mut mac = Hmac::new(Sha1::new(), &self.secret_key);
        let encoded_data = message.as_bytes().to_base64(STANDARD);

        mac.input(encoded_data.as_bytes());

        let signature = mac.result();
        let result = format!("{}--{}", encoded_data, signature.code().to_hex());

        result.clone()
    }
}

impl AesHmacEncryptor {
    /// Create a new AesHmacEncryptor object
    pub fn new(secret: &str, salt: &str, sign_salt: &str, key_params: DerivedKeyParams) -> Result<AesHmacEncryptor> {
        let salts = vec![salt, sign_salt];
        let keys = create_derived_keys(&salts, secret, key_params);

        match (keys.first(), keys.last()) {
            (Some(cipher_key), Some(sig_key)) => {
                Ok(AesHmacEncryptor {
                    key_size: AesKeySize::KeySize256,
                    secret_key: cipher_key.to_vec(),
                    verifier: Verifier {
                        secret_key: sig_key.to_vec()
                    }
                })
            }

            _ => bail!(ErrorKind::KeyDerivationFailure)
        }
    }

    /// Set the cipher using the `KeySize` enum
    pub fn set_cipher_key_size(&mut self, key_size: KeySize) -> &mut AesHmacEncryptor {
        self.key_size = AesKeySize::from(key_size);
        self
    }
}

impl Encryptor for AesHmacEncryptor {
    /// Decrypt and verify a message generated by a compatible Encryptor. The message must first be
    /// verified before decryption is attempted.
    fn decrypt_and_verify(&self, message: &str) -> Result<Vec<u8>> {
        let decoded = self.verifier.verify(message)?;
        let msg_split = split_by_n_dashes_from_u8_slice(2, &decoded)?;

        let cipher_text = msg_split[0].from_base64()?;
        let iv = msg_split[1].from_base64()?;

        let mut decryptor = cbc_decryptor(self.key_size, &self.secret_key, &iv, blockmodes::PkcsPadding);

        let mut final_result: Vec<u8> = Vec::new();
        let mut buffer = vec![0; 4096];

        let mut read_buffer = buffer::RefReadBuffer::new(&cipher_text);
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
                Ok(buffer_result) => {
                    final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

                    match buffer_result {
                        BufferResult::BufferUnderflow => break,
                        BufferResult::BufferOverflow => continue
                    }
                }

                Err(_) => bail!(ErrorKind::InvalidMessage)
            }
        }

        Ok(final_result)
    }

    /// Encrypt and sign a message from the input message. This message can be consumed by a
    /// compatible Encryptor
    fn encrypt_and_sign(&self, message: &str) -> Result<String> {
        let random_iv = random_iv(16)?;

        let mut encryptor = cbc_encryptor(self.key_size, &self.secret_key, &random_iv, blockmodes::PkcsPadding);

        let mut cipher_result: Vec<u8> = Vec::new();
        let mut read_buffer = buffer::RefReadBuffer::new(message.as_bytes());
        let mut buffer = vec![0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

        loop {
            match encryptor.encrypt(&mut read_buffer, &mut write_buffer, true) {
                Ok(buffer_result) => {
                    cipher_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

                    match buffer_result {
                        BufferResult::BufferUnderflow => break,
                        BufferResult::BufferOverflow => continue
                    }
                }

                Err(_) => bail!("Encryptor failed")
            }
        }

        let encoded_ctxt = cipher_result.to_base64(STANDARD);
        let encoded_iv = random_iv.to_base64(STANDARD);

        Ok(self.verifier.generate(&format!("{}--{}", encoded_ctxt, encoded_iv)))
    }
}

impl AesGcmEncryptor {
    /// Create a new AesGcmEncryptor object
    pub fn new(secret: &str, salt: &str, key_params: DerivedKeyParams) -> Result<AesGcmEncryptor> {
        let salts = vec![salt];
        let keys = create_derived_keys(&salts, secret, key_params);

        match keys.first() {
            Some(cipher_key) => {
                Ok(AesGcmEncryptor {
                    key_size: AesKeySize::KeySize256,
                    secret_key: cipher_key.to_vec(),
                })
            }

            _ => bail!(ErrorKind::KeyDerivationFailure)
        }
    }

    /// Set the cipher using the `KeySize` enum
    pub fn set_cipher_key_size(&mut self, key_size: KeySize) -> &mut AesGcmEncryptor {
        self.key_size = AesKeySize::from(key_size);
        self
    }
}

impl Encryptor for AesGcmEncryptor {
    /// Decrypt a message, using AEAD, generated by a compatible Encryptor. The message must first
    /// be verified before decryption is attempted.
    fn decrypt_and_verify(&self, message: &str) -> Result<Vec<u8>> {
        let msg_split = split_by_n_dashes(3, &message)?;

        let cipher_text = msg_split[0].from_base64()?;
        let iv = msg_split[1].from_base64()?;
        let auth_tag = msg_split[2].from_base64()?;

        let mut decryptor = AesGcm::new(self.key_size, &self.secret_key[0..32], &iv[0..12], &vec![0; 0]);
        let mut output: Vec<u8> = vec![0; cipher_text.len()];

        match decryptor.decrypt(&cipher_text, &mut output, &auth_tag) {
            true => Ok(output),
            false => bail!(ErrorKind::InvalidMessage)
        }
    }

    /// Encrypt a message, using AEAD, from the input message. This message can be consumed by a
    /// compatible Encryptor
    fn encrypt_and_sign(&self, message: &str) -> Result<String> {
        let random_iv = random_iv(12)?;
        let aad = vec![0; 0];

        let mut encryptor = AesGcm::new(self.key_size, &self.secret_key[0..32], &random_iv, &aad);

        let mut output: Vec<u8> = vec![0; message.len()];
        let mut auth_tag: Vec<u8> = vec![0; 16];

        encryptor.encrypt(message.as_bytes(), &mut output, &mut auth_tag);

        let encoded_ctxt = output.to_base64(STANDARD);
        let encoded_iv = random_iv.to_base64(STANDARD);
        let encoded_tag = auth_tag.to_base64(STANDARD);

        Ok(format!("{}--{}--{}", encoded_ctxt, encoded_iv, encoded_tag))
    }
}

#[cfg(test)]
mod tests {
    // assert_error_kind!(err, kind)
    macro_rules! assert_error_kind {
        ($err:expr, $kind:pat) => (match *$err.kind() {
            $kind => assert!(true, "{:?} is of kind {:?}", $err, stringify!($kind)),
            _     => assert!(false, "{:?} is NOT of kind {:?}", $err, stringify!($kind))
        });
    }

    use std::str;
    use {Verifier, Encryptor, KeySize, AesHmacEncryptor, AesGcmEncryptor, DerivedKeyParams, ErrorKind};

    #[test]
    fn is_valid_message_returns_true_for_valid_signatures() {
        let data = "eyJrZXkiOiJ2YWx1ZSJ9";
        let sig  = "fa115453dbb4a28277b1ba07ef4c7437621f5d72";

        let verifier = Verifier::new("helloworld");

        assert_eq!(verifier.is_valid_message(data, sig), true);
    }

    #[test]
    fn is_valid_message_returns_false_for_invalid_signatures() {
        let data = "eyJrZXkiOiJ2YWx1ZSJ9";
        let sig  = "05330518df0e21fb9beec7a71a5f5f951c3f5254";

        let verifier = Verifier::new("helloworld");

        assert_eq!(verifier.is_valid_message(data, sig), false);
    }

    #[test]
    fn is_valid_message_returns_false_for_invalid_messages() {
        let data = "baddata";
        let sig  = "badsig";

        let verifier = Verifier::new("helloworld");

        assert_eq!(verifier.is_valid_message(data, sig), false);
    }

    #[test]
    fn verify_returns_decoded_message_for_valid_signatures() {
        let msg = "eyJrZXkiOiJ2YWx1ZSJ9--fa115453dbb4a28277b1ba07ef4c7437621f5d72";

        let verifier = Verifier::new("helloworld");

        assert_eq!(verifier.verify(msg).unwrap(), "{\"key\":\"value\"}".as_bytes());
    }

    #[test]
    fn verify_returns_invalid_signature_error_for_wrong_key() {
        let msg = "eyJrZXkiOiJ2YWx1ZSJ9--05330518df0e21fb9beec7a71a5f5f951c3f5254";

        let verifier = Verifier::new("helloworld");

        assert_error_kind!(verifier.verify(msg).unwrap_err(), ErrorKind::InvalidSignature);
    }

    #[test]
    fn verify_returns_invalid_message_error_for_empty_message() {
        let msg = "";

        let verifier = Verifier::new("helloworld");

        assert_error_kind!(verifier.verify(msg).unwrap_err(), ErrorKind::InvalidMessage);
    }

    #[test]
    fn generate_returns_signed_and_encoded_string(){
        let verifier = Verifier::new("helloworld");
        let expected = "eyJrZXkiOiJ2YWx1ZSJ9--fa115453dbb4a28277b1ba07ef4c7437621f5d72";

        assert_eq!(verifier.generate("{\"key\":\"value\"}"), expected.to_string());
    }

    #[test]
    fn aes_hamc_decrypt_and_verify_returns_decoded_message_for_valid_messages() {
        let msg = "c20wSnp6Z1o1U2MyWDVjU3BPeWNNQT09LS1JOWNyR25LdDRpZUUvcmoxVTdoSTNRPT0=--a79c9522355e55bf8e4302c66d8bf5638f1a50ec";

        let dkp = DerivedKeyParams::default();
        let encryptor = AesHmacEncryptor::new( "helloworld", "test salt", "test signed salt", dkp).unwrap();

        assert_eq!(encryptor.decrypt_and_verify(msg).unwrap(), "{\"key\":\"value\"}".as_bytes());
    }

    #[test]
    fn aes_hamc_decrypt_and_verify_returns_invalid_signature_error_for_wrong_key(){
        let msg = "SnRXQXFhOE9WSGg2QmVGUDdHdkhNZz09LS1vcjFWcm53VU40YmV0SVcwdWFlK2NRPT0=--c879b51cbd92559d4d684c406b3aaebfbc958e9d";

        let dkp = DerivedKeyParams::default();
        let encryptor = AesHmacEncryptor::new("helloworld", "test salt", "test signed salt", dkp).unwrap();

        assert_error_kind!(encryptor.decrypt_and_verify(msg).unwrap_err(), ErrorKind::InvalidSignature);
    }

    #[test]
    fn aes_hamc_decrypt_and_verify_returns_invalid_message_for_empty_message(){
        let msg = "";

        let dkp = DerivedKeyParams::default();
        let encryptor = AesHmacEncryptor::new("helloworld", "test salt", "test signed salt", dkp).unwrap();

        assert_error_kind!(encryptor.decrypt_and_verify(msg).unwrap_err(), ErrorKind::InvalidMessage);
    }

    #[test]
    fn aes_hamc_encrypt_and_sign_returns_encrypted_and_signed_decryptable_and_verifiable_string(){
        let dkp = DerivedKeyParams::default();
        let encryptor = AesHmacEncryptor::new("helloworld", "test salt", "test signed salt", dkp).unwrap();

        let message = encryptor.encrypt_and_sign("{\"key\":\"value\"}").unwrap();

        assert_eq!(encryptor.decrypt_and_verify(&message).unwrap(), "{\"key\":\"value\"}".as_bytes());
    }

    #[test]
    fn aes_hamc_decrypt_and_verify_returns_decoded_message_with_non_default_cipher_for_valid_messages() {
        let msg = "RXFQajB4VzR3QytRQ0NpQXlGUFFTdz09LS0ycUZlcWFXNlRsb1phanMvcHlwVCtRPT0=--5d4739f859e1f730dc0ae7abfb21160c9f00dae6";

        let dkp = DerivedKeyParams::default();
        let mut encryptor = AesHmacEncryptor::new( "helloworld", "test salt", "test signed salt", dkp).unwrap();

        encryptor.set_cipher_key_size(KeySize::Aes192);

        assert_eq!(encryptor.decrypt_and_verify(msg).unwrap(), "{\"key\":\"value\"}".as_bytes());
    }

    #[test]
    fn aes_hamc_encrypt_and_sign_returns_encrypted_and_signed_decryptable_and_verifiable_string_with_non_default_cipher(){
        let dkp = DerivedKeyParams::default();
        let mut encryptor = AesHmacEncryptor::new("helloworld", "test salt", "test signed salt", dkp).unwrap();

        encryptor.set_cipher_key_size(KeySize::Aes192);

        let message = encryptor.encrypt_and_sign("{\"key\":\"value\"}").unwrap();

        assert_eq!(encryptor.decrypt_and_verify(&message).unwrap(), "{\"key\":\"value\"}".as_bytes());
    }

    #[test]
    fn aes_gcm_decrypt_and_verify_returns_decoded_message_for_valid_messages() {
        let msg = "H9msESjs5e8I6utXGnk0--4UI1B/xoA1MIR3A3--DHpzaZ7LMhFsWXzEbLiOCA==";

        let dkp = DerivedKeyParams::default();
        let encryptor = AesGcmEncryptor::new( "helloworld", "test salt", dkp).unwrap();

        assert_eq!(encryptor.decrypt_and_verify(msg).unwrap(), "{\"key\":\"value\"}".as_bytes());
    }

    #[test]
    fn aes_gcm_decrypt_and_verify_returns_invalid_message_error_for_wrong_key(){
        let msg = "Rhlx3KvutaC3AU1gi7pg--5T4OYITxIw56qdfL--pcc0hZjYYP/5xgTRYFqnkA==";

        let dkp = DerivedKeyParams::default();
        let encryptor = AesGcmEncryptor::new("helloworld", "test salt", dkp).unwrap();

        assert_error_kind!(encryptor.decrypt_and_verify(msg).unwrap_err(), ErrorKind::InvalidMessage);
    }

    #[test]
    fn aes_gcm_decrypt_and_verify_returns_invalid_message_for_empty_message(){
        let msg = "";

        let dkp = DerivedKeyParams::default();
        let encryptor = AesGcmEncryptor::new("helloworld", "test signed salt", dkp).unwrap();

        assert_error_kind!(encryptor.decrypt_and_verify(msg).unwrap_err(), ErrorKind::InvalidMessage);
    }

    #[test]
    fn aes_gcm_encrypt_and_sign_returns_encrypted_and_signed_decryptable_and_verifiable_string(){
        let dkp = DerivedKeyParams::default();
        let encryptor = AesGcmEncryptor::new("helloworld", "test salt", dkp).unwrap();

        let message = encryptor.encrypt_and_sign("{\"key\":\"value\"}").unwrap();

        assert_eq!(encryptor.decrypt_and_verify(&message).unwrap(), "{\"key\":\"value\"}".as_bytes());
    }
}
