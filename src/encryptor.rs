use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use aes_gcm::{
    aead::{consts::U12, KeyInit},
    AeadInOut, AesGcm, Nonce, Tag,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    codec::{extract_part, read_rotated},
    metadata, Digest, Encoding, Error, MessageOptions, MetadataFormat, Result, Verifier,
    VerifyOptions,
};

/// Rails-compatible AES ciphers. GCM uses a 12-byte nonce and a 16-byte authentication tag.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Cipher {
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes192Gcm,
    #[default]
    Aes256Gcm,
}

impl Cipher {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Cbc | Self::Aes128Gcm => 16,
            Self::Aes192Cbc | Self::Aes192Gcm => 24,
            Self::Aes256Cbc | Self::Aes256Gcm => 32,
        }
    }

    fn is_gcm(self) -> bool {
        matches!(self, Self::Aes128Gcm | Self::Aes192Gcm | Self::Aes256Gcm)
    }
    fn iv_len(self) -> usize {
        if self.is_gcm() {
            12
        } else {
            16
        }
    }
}

#[derive(Clone)]
struct Config {
    key: Vec<u8>,
    cipher: Cipher,
    verifier: Verifier,
    encoding: Encoding,
    metadata: MetadataFormat,
}

/// ActiveSupport-compatible authenticated encryption, defaulting to AES-256-GCM.
#[derive(Clone)]
pub struct Encryptor {
    config: Config,
    rotations: Vec<Config>,
}

pub struct EncryptorBuilder {
    key: Vec<u8>,
    signing_key: Option<Vec<u8>>,
    cipher: Cipher,
    digest: Digest,
    encoding: Encoding,
    metadata: MetadataFormat,
}

impl EncryptorBuilder {
    pub fn cipher(mut self, cipher: Cipher) -> Self {
        self.cipher = cipher;
        self
    }
    /// Separate CBC signing key; defaults to the encryption key and is ignored for GCM.
    pub fn signing_key(mut self, key: impl AsRef<[u8]>) -> Self {
        self.signing_key = Some(key.as_ref().to_vec());
        self
    }
    /// CBC signing digest; ignored for GCM.
    pub fn digest(mut self, digest: Digest) -> Self {
        self.digest = digest;
        self
    }
    pub fn encoding(mut self, encoding: Encoding) -> Self {
        self.encoding = encoding;
        self
    }
    pub fn metadata_format(mut self, format: MetadataFormat) -> Self {
        self.metadata = format;
        self
    }

    pub fn build(self) -> Result<Encryptor> {
        if self.key.len() != self.cipher.key_len() {
            return Err(Error::InvalidKeyLength {
                expected: self.cipher.key_len(),
                actual: self.key.len(),
            });
        }
        let verifier = Verifier::builder(self.signing_key.as_deref().unwrap_or(&self.key))
            .digest(self.digest)
            .encoding(self.encoding)
            .build();
        Ok(Encryptor {
            config: Config {
                key: self.key,
                cipher: self.cipher,
                verifier,
                encoding: self.encoding,
                metadata: self.metadata,
            },
            rotations: Vec::new(),
        })
    }
}

impl Config {
    fn encrypt(&self, data: &[u8]) -> Result<String> {
        let mut iv = vec![0; self.cipher.iv_len()];
        getrandom::fill(&mut iv).map_err(|_| Error::Randomness)?;
        macro_rules! cbc_encrypt {
            ($aes:ty) => {
                cbc::Encryptor::<$aes>::new_from_slices(&self.key, &iv)
                    .map_err(|_| Error::InvalidMessage)?
                    .encrypt_padded_vec::<Pkcs7>(data)
            };
        }
        if !self.cipher.is_gcm() {
            let ciphertext = match self.cipher {
                Cipher::Aes128Cbc => cbc_encrypt!(aes::Aes128),
                Cipher::Aes192Cbc => cbc_encrypt!(aes::Aes192),
                Cipher::Aes256Cbc => cbc_encrypt!(aes::Aes256),
                _ => unreachable!(),
            };
            return Ok(self.verifier.generate(format!(
                "{}--{}",
                self.encoding.encode(ciphertext),
                self.encoding.encode(iv)
            )));
        }
        let mut ciphertext = data.to_vec();
        let nonce = Nonce::<U12>::try_from(iv.as_slice()).map_err(|_| Error::InvalidMessage)?;
        macro_rules! gcm_encrypt {
            ($aes:ty) => {
                AesGcm::<$aes, U12>::new_from_slice(&self.key)
                    .map_err(|_| Error::InvalidMessage)?
                    .encrypt_inout_detached(&nonce, &[], ciphertext.as_mut_slice().into())
                    .map_err(|_| Error::InvalidMessage)?
            };
        }
        let tag = match self.cipher {
            Cipher::Aes128Gcm => gcm_encrypt!(aes::Aes128),
            Cipher::Aes192Gcm => gcm_encrypt!(aes::Aes192),
            Cipher::Aes256Gcm => gcm_encrypt!(aes::Aes256),
            _ => unreachable!(),
        };
        Ok(format!(
            "{}--{}--{}",
            self.encoding.encode(ciphertext),
            self.encoding.encode(iv),
            self.encoding.encode(tag)
        ))
    }

    fn decrypt(&self, message: &str) -> Result<Vec<u8>> {
        // CBC authentication must finish before any decryption or padding validation.
        let verified;
        let message = if self.cipher.is_gcm() {
            message
        } else {
            verified = self
                .verifier
                .verify(message)
                .map_err(|_| Error::InvalidMessage)?;
            std::str::from_utf8(&verified).map_err(|_| Error::InvalidMessage)?
        };
        let (message, tag) = if self.cipher.is_gcm() {
            let (message, tag) = extract_part(message, self.encoding.encoded_len(16))?;
            (message, self.encoding.decode(tag)?)
        } else {
            (message, Vec::new())
        };
        let (ciphertext, iv) =
            extract_part(message, self.encoding.encoded_len(self.cipher.iv_len()))?;
        let iv = self.encoding.decode(iv)?;
        let mut ciphertext = self.encoding.decode(ciphertext)?;
        if iv.len() != self.cipher.iv_len() || (self.cipher.is_gcm() && tag.len() != 16) {
            return Err(Error::InvalidMessage);
        }
        macro_rules! cbc_decrypt {
            ($aes:ty) => {
                cbc::Decryptor::<$aes>::new_from_slices(&self.key, &iv)
                    .map_err(|_| Error::InvalidMessage)?
                    .decrypt_padded_vec::<Pkcs7>(&ciphertext)
                    .map_err(|_| Error::InvalidMessage)
            };
        }
        if !self.cipher.is_gcm() {
            return match self.cipher {
                Cipher::Aes128Cbc => cbc_decrypt!(aes::Aes128),
                Cipher::Aes192Cbc => cbc_decrypt!(aes::Aes192),
                Cipher::Aes256Cbc => cbc_decrypt!(aes::Aes256),
                _ => unreachable!(),
            };
        }
        let nonce = Nonce::<U12>::try_from(iv.as_slice()).map_err(|_| Error::InvalidMessage)?;
        let tag = Tag::try_from(tag.as_slice()).map_err(|_| Error::InvalidMessage)?;
        macro_rules! gcm_decrypt {
            ($aes:ty) => {
                AesGcm::<$aes, U12>::new_from_slice(&self.key)
                    .map_err(|_| Error::InvalidMessage)?
                    .decrypt_inout_detached(&nonce, &[], ciphertext.as_mut_slice().into(), &tag)
                    .map_err(|_| Error::InvalidMessage)?
            };
        }
        match self.cipher {
            Cipher::Aes128Gcm => gcm_decrypt!(aes::Aes128),
            Cipher::Aes192Gcm => gcm_decrypt!(aes::Aes192),
            Cipher::Aes256Gcm => gcm_decrypt!(aes::Aes256),
            _ => unreachable!(),
        }
        Ok(ciphertext)
    }
}

impl Encryptor {
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self> {
        Self::builder(key).build()
    }

    pub fn builder(key: impl AsRef<[u8]>) -> EncryptorBuilder {
        EncryptorBuilder {
            key: key.as_ref().to_vec(),
            signing_key: None,
            cipher: Cipher::default(),
            digest: Digest::default(),
            encoding: Encoding::default(),
            metadata: MetadataFormat::default(),
        }
    }

    pub fn rotate(&mut self, fallback: Self) -> &mut Self {
        self.rotations.push(fallback.config);
        self.rotations.extend(fallback.rotations);
        self
    }

    /// Encrypt already serialized bytes without wrapping metadata.
    pub fn encrypt_and_sign(&self, data: impl AsRef<[u8]>) -> Result<String> {
        self.config.encrypt(data.as_ref())
    }

    /// Authenticate and decrypt raw bytes. Use `decrypt_and_verify_json` to enforce metadata.
    pub fn decrypt_and_verify(&self, message: &str) -> Result<Vec<u8>> {
        read_rotated(&self.config, &self.rotations, |config| {
            config.decrypt(message)
        })
    }

    pub fn encrypt_and_sign_json<T: Serialize + ?Sized>(
        &self,
        value: &T,
        options: MessageOptions<'_>,
    ) -> Result<String> {
        self.encrypt_and_sign(metadata::serialize(value, options, self.config.metadata)?)
    }

    /// Invalid tokens produce errors; expired or purpose-mismatched messages return `None`.
    pub fn decrypt_and_verify_json<T: DeserializeOwned>(
        &self,
        message: &str,
        options: VerifyOptions<'_>,
    ) -> Result<Option<T>> {
        match read_rotated(&self.config, &self.rotations, |config| {
            metadata::deserialize(&config.decrypt(message)?, options)
        }) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.is_content() => Ok(None),
            Err(error) => Err(error),
        }
    }
}
