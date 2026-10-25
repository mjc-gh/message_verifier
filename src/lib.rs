#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod codec;
mod digest;
mod encryptor;
mod error;
mod key_generator;
mod metadata;
mod verifier;

pub use codec::Encoding;
pub use digest::Digest;
pub use encryptor::{Cipher, Encryptor, EncryptorBuilder};
pub use error::{Error, Result};
pub use key_generator::KeyGenerator;
pub use metadata::{MessageOptions, MetadataFormat, VerifyOptions};
pub use verifier::{Verifier, VerifierBuilder};
