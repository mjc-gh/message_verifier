extern crate crypto;
extern crate rand;
extern crate rustc_serialize;

#[macro_use]
extern crate error_chain;

use crypto::{buffer, blockmodes};
use crypto::aes::{cbc_decryptor, cbc_encryptor, KeySize as AesKeySize};
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

pub struct Verifier {
    secret_key: Vec<u8>
}

pub struct Encryptor {
    secret_key: Vec<u8>,
    verifier: Verifier
}

pub struct DerivedKeyParams {
    size: u32,
    iterations: u32
}

impl Default for DerivedKeyParams {
    fn default() -> DerivedKeyParams {
        DerivedKeyParams { size: 64, iterations: 1000 }
    }
}

pub fn create_derived_keys(secret: &str, salts: &Vec<&str>, key_params: DerivedKeyParams) -> Vec<Vec<u8>> {
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

fn split_by_dashes(message: &str) -> Result<(&str, &str)> {
    let split: Vec<&str> = message.splitn(2, "--").collect();

    match split.len() {
        2 => Ok((split.first().unwrap(), split.last().unwrap())),
        _ => bail!(ErrorKind::InvalidMessage)
    }
}

fn split_by_dashes_from_u8_slice(slice: &[u8]) -> Result<(&str, &str)> {
    match from_utf8(slice) {
        Ok(string) => split_by_dashes(string),
        Err(_) => bail!(ErrorKind::InvalidMessage)
    }
}

impl Verifier {
    pub fn new(secret: &str) -> Verifier {
        Verifier {
            secret_key: secret.bytes().collect()
        }
    }

    pub fn verify(&self, message: &str) -> Result<Vec<u8>> {
        let (encoded_data, signature) = try!(split_by_dashes(&message));

        match self.is_valid_message(encoded_data, signature) {
            true  => Ok(try!(encoded_data.from_base64())),
            false => bail!(ErrorKind::InvalidSignature)
        }
    }

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

    pub fn generate(&self, message: &str) -> String {
        let mut mac = Hmac::new(Sha1::new(), &self.secret_key);
        let encoded_data = message.as_bytes().to_base64(STANDARD);

        mac.input(encoded_data.as_bytes());

        let signature = mac.result();
        let result = format!("{}--{}", encoded_data, signature.code().to_hex());

        result.clone()
    }
}

impl Encryptor {
    pub fn new(secret: &str, salt: &str, sign_salt: &str, key_params: DerivedKeyParams) -> Result<Encryptor> {
        let salts = vec![salt, sign_salt];
        let keys = create_derived_keys(secret, &salts, key_params);

        match (keys.first(), keys.last()) {
            (Some(cipher_key), Some(sig_key)) => {
                Ok(Encryptor {
                    secret_key: cipher_key.to_vec(),
                    verifier: Verifier {
                        secret_key: sig_key.to_vec()
                    }
                })
            }

            _ => bail!(ErrorKind::KeyDerivationFailure)
        }
    }

    pub fn decrypt_and_verify(&self, message: &str) -> Result<Vec<u8>> {
        let decoded = try!(self.verifier.verify(message));
        let (encoded_cipher_text, encoded_iv) = try!(split_by_dashes_from_u8_slice(&decoded));

        let cipher_text = try!(encoded_cipher_text.from_base64());
        let iv = try!(encoded_iv.from_base64());

        let key_sz = AesKeySize::KeySize256; // TODO make configurable
        let mut decryptor = cbc_decryptor(key_sz, &self.secret_key, &iv, blockmodes::PkcsPadding);

        let mut final_result: Vec<u8> = Vec::new();
        let mut buffer = [0; 4096];

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

                Err(_) => return bail!(ErrorKind::InvalidMessage)
            }
        }

        Ok(final_result)
    }

    pub fn encrypt_and_sign(&self, message: &str) -> Result<String> {
        let random_iv = try!(random_iv(16));
        let key_sz = AesKeySize::KeySize256; // TODO make configurable

        let mut encryptor = cbc_encryptor(key_sz, &self.secret_key, &random_iv, blockmodes::PkcsPadding);

        let mut cipher_result: Vec<u8> = Vec::new();
        let mut read_buffer = buffer::RefReadBuffer::new(message.as_bytes());
        let mut buffer = [0; 4096];
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

                Err(_) => return bail!("Encryptor failed")
            }
        }

        let encoded_ctxt = cipher_result.to_base64(STANDARD);
        let encoded_iv = random_iv.to_base64(STANDARD);

        Ok(self.verifier.generate(&format!("{}--{}", encoded_ctxt, encoded_iv)))
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

    use Verifier;
    use Encryptor;
    use DerivedKeyParams;
    use ErrorKind;

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
    fn decrypt_and_verify_returns_decoded_message_for_valid_messages() {
        let msg = "c20wSnp6Z1o1U2MyWDVjU3BPeWNNQT09LS1JOWNyR25LdDRpZUUvcmoxVTdoSTNRPT0=--a79c9522355e55bf8e4302c66d8bf5638f1a50ec";

        let dkp = DerivedKeyParams::default();
        let encryptor = Encryptor::new( "helloworld", "test salt", "test signed salt", dkp).unwrap();

        assert_eq!(encryptor.decrypt_and_verify(msg).unwrap(), "{\"key\":\"value\"}".as_bytes());
    }

    #[test]
    fn decrypt_and_verify_returns_invalid_signature_error_for_wrong_key(){
        let msg = "SnRXQXFhOE9WSGg2QmVGUDdHdkhNZz09LS1vcjFWcm53VU40YmV0SVcwdWFlK2NRPT0=--c879b51cbd92559d4d684c406b3aaebfbc958e9d";

        let dkp = DerivedKeyParams::default();
        let encryptor = Encryptor::new("helloworld", "test salt", "test signed salt", dkp).unwrap();

        assert_error_kind!(encryptor.decrypt_and_verify(msg).unwrap_err(), ErrorKind::InvalidSignature);
    }

    #[test]
    fn decrypt_and_verify_returns_invalid_message_for_empty_message(){
        let msg = "";

        let dkp = DerivedKeyParams::default();
        let encryptor = Encryptor::new("helloworld", "test salt", "test signed salt", dkp).unwrap();

        assert_error_kind!(encryptor.decrypt_and_verify(msg).unwrap_err(), ErrorKind::InvalidMessage);
    }

    #[test]
    fn generate_returns_signed_and_encoded_string(){
        let verifier = Verifier::new("helloworld");
        let expected = "eyJrZXkiOiJ2YWx1ZSJ9--fa115453dbb4a28277b1ba07ef4c7437621f5d72";

        assert_eq!(verifier.generate("{\"key\":\"value\"}"), expected.to_string());
    }

    #[test]
    fn encrypt_and_sign_returns_encrypted_and_signed_decryptable_and_verifiable_string(){
        let dkp = DerivedKeyParams::default();
        let encryptor = Encryptor::new("helloworld", "test salt", "test signed salt", dkp).unwrap();

        let message = encryptor.encrypt_and_sign("{\"key\":\"value\"}").unwrap();

        assert_eq!(encryptor.decrypt_and_verify(&message).unwrap(), "{\"key\":\"value\"}".as_bytes());
    }
}
