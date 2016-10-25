extern crate crypto;
extern crate rustc_serialize;

//use crypto::{buffer, blockmodes};
//use crypto::aes::{cbc_decryptor, KeySize as AesKeySize};
use crypto::hmac::Hmac;
use crypto::mac::{Mac};
use crypto::sha1::Sha1;
//use crypto::symmetriccipher::{SymmetricCipherError};
//use crypto::pbkdf2::pbkdf2;
use crypto::util::fixed_time_eq;

use rustc_serialize::hex::{FromHex};
use rustc_serialize::base64::FromBase64;

pub struct Verifier<'a> {
    secret_key: &'a[u8]
}

#[derive(Debug, PartialEq)]
pub enum VerifierError {
    MessageParse,
    InvalidSignature,
    DecodePayload
}

//fn create_derived_key(secret: &str, salt: &str, key_iters: u32, key_sz: u32) -> Vec<u8> {
    //let mut mac = Hmac::new(Sha1::new(), secret.as_bytes());
    //let mut result: Vec<u8> = vec![0; key_sz as usize];

    //pbkdf2(&mut mac, salt.as_bytes(), key_iters, &mut result);

    //result
//}

fn split_by_dashes<'a>(message: &'a String) -> Option<(&'a str, &'a str)> {
    let split: Vec<&str> = message.splitn(2, "--").collect();

    match split.len() {
        2 => Some((split.first().unwrap(), split.last().unwrap())),
        _ => None
    }
}

impl<'a> Verifier<'a> {
    pub fn new(secret: &'a str) -> Verifier<'a> {
        Verifier {
            secret_key: &secret.as_bytes()
        }
    }

    pub fn verify(&self, message: String) -> Result<Vec<u8>, VerifierError> {
        match split_by_dashes(&message) {
            Some((data, signature)) => {
                match self.is_valid_message(data, signature) {
                    true => {
                        match data.from_base64() {
                            Ok(decoded) => Ok(decoded),
                            Err(_) => Err(VerifierError::DecodePayload)
                        }
                    },

                    false => Err(VerifierError::InvalidSignature)
                }
            },

            None => Err(VerifierError::MessageParse)
        }
    }

    pub fn is_valid_message(&self, data: &'a str, signature: &'a str) -> bool {
        match signature.from_hex() {
            Ok(sig_bytes) => {
                let mut mac = Hmac::new(Sha1::new(), &self.secret_key);

                mac.input(data.as_bytes());

                fixed_time_eq(mac.result().code(), &sig_bytes)
            },

            Err(_) => false
        }
    }
}

//pub struct Encryptor {
    //derived_key: Vec<u8>,
    //verifier: Verifier
//}

//impl Encryptor {
    //pub fn new(secret: &str, salt: &str, sign_salt: &str, key_iters: u32, key_sz: u32) -> Encryptor {
        //Encryptor {
            //derived_key: create_derived_key(secret, salt, key_iters, key_sz)
            //verifier: Verifier::new(secret, sign_salt, key_iters, key_sz)
        //}
    //}

    //pub fn decrypt_and_verify(value: String) -> Option<bool> {
        //match value.find("--") {
            //Some(index) => {
                //let (data, signature) = value.split_at(index);

            //}

            //// TODO
            //// first verify data against signature with wrapped Verifier

            //// TODO
            //// base64 decode data, split by '--'
            //// message payload is first, IV is second

            //_ => None
        //}
    //}
//}

#[cfg(test)]
mod tests {
    use Verifier;
    use VerifierError;

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
        let msg = "eyJrZXkiOiJ2YWx1ZSJ9--fa115453dbb4a28277b1ba07ef4c7437621f5d72".to_string();

        let verifier = Verifier::new("helloworld");

        assert_eq!(verifier.verify(msg).unwrap(), "{\"key\":\"value\"}".as_bytes());
    }

    #[test]
    fn verify_returns_error_for_invalid_signatures() {
        let msg = "eyJrZXkiOiJ2YWx1ZSJ9--05330518df0e21fb9beec7a71a5f5f951c3f5254".to_string();

        let verifier = Verifier::new("helloworld");

        assert_eq!(verifier.verify(msg).unwrap_err(), VerifierError::InvalidSignature);
    }

    #[test]
    fn verify_returns_error_for_invalid_data() {
        let msg = "fa115453dbb4a28277b1ba07ef4c7437621f5d72".to_string();

        let verifier = Verifier::new("helloworld");

        assert_eq!(verifier.verify(msg).unwrap_err(), VerifierError::MessageParse);
    }
}
