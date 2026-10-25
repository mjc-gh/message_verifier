use serde::{de::DeserializeOwned, Serialize};

use crate::{
    codec::{extract_part, read_rotated},
    metadata, Digest, Encoding, Error, MessageOptions, MetadataFormat, Result, VerifyOptions,
};

#[derive(Clone)]
struct Config {
    secret: Vec<u8>,
    digest: Digest,
    encoding: Encoding,
    metadata: MetadataFormat,
}

/// ActiveSupport-compatible message signing. Signed messages are readable, not encrypted.
#[derive(Clone)]
pub struct Verifier {
    config: Config,
    rotations: Vec<Config>,
}

pub struct VerifierBuilder {
    config: Config,
}

impl VerifierBuilder {
    pub fn digest(mut self, digest: Digest) -> Self {
        self.config.digest = digest;
        self
    }
    pub fn encoding(mut self, encoding: Encoding) -> Self {
        self.config.encoding = encoding;
        self
    }
    pub fn metadata_format(mut self, format: MetadataFormat) -> Self {
        self.config.metadata = format;
        self
    }
    pub fn build(self) -> Verifier {
        Verifier {
            config: self.config,
            rotations: Vec::new(),
        }
    }
}

impl Config {
    fn extract<'a>(&self, message: &'a str) -> Result<&'a str> {
        let (data, signature) =
            extract_part(message, self.digest.hex_len()).map_err(|_| Error::InvalidSignature)?;
        if data.is_empty() || !self.digest.verify(&self.secret, data.as_bytes(), signature) {
            return Err(Error::InvalidSignature);
        }
        Ok(data)
    }

    fn read(&self, message: &str) -> Result<Vec<u8>> {
        let encoded = self.extract(message)?;
        self.encoding
            .decode(encoded)
            .or_else(|_| match self.encoding {
                Encoding::Standard => Encoding::UrlSafe.decode(encoded),
                Encoding::UrlSafe => Encoding::Standard.decode(encoded),
            })
    }

    fn generate(&self, data: &[u8]) -> String {
        let encoded = self.encoding.encode(data);
        let signature = self.digest.sign(&self.secret, encoded.as_bytes());
        format!("{encoded}--{signature}")
    }
}

impl Verifier {
    /// SHA1 and standard Base64 match standalone ActiveSupport signing defaults.
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self::builder(secret).build()
    }

    pub fn builder(secret: impl AsRef<[u8]>) -> VerifierBuilder {
        VerifierBuilder {
            config: Config {
                secret: secret.as_ref().to_vec(),
                digest: Digest::Sha1,
                encoding: Encoding::Standard,
                metadata: MetadataFormat::Current,
            },
        }
    }

    /// Add an explicitly configured read-only fallback. Generation always uses the primary.
    pub fn rotate(&mut self, fallback: Self) -> &mut Self {
        self.rotations.push(fallback.config);
        self.rotations.extend(fallback.rotations);
        self
    }

    /// Sign already serialized bytes without interpreting JSON or metadata.
    pub fn generate(&self, data: impl AsRef<[u8]>) -> String {
        self.config.generate(data.as_ref())
    }

    /// Authenticate and decode raw bytes, including configured rotations.
    /// This low-level method does not enforce JSON metadata; use `verify_json` for that.
    pub fn verify(&self, message: &str) -> Result<Vec<u8>> {
        read_rotated(&self.config, &self.rotations, |config| config.read(message)).map_err(
            |error| {
                if error.is_rejected() {
                    Error::InvalidSignature
                } else {
                    error
                }
            },
        )
    }

    pub fn verified(&self, message: &str) -> Option<Vec<u8>> {
        self.verify(message).ok()
    }

    /// Check the primary signature only, without decoding or enforcing metadata (like Rails).
    pub fn valid_message(&self, message: &str) -> bool {
        self.config.extract(message).is_ok()
    }

    pub fn generate_json<T: Serialize + ?Sized>(
        &self,
        value: &T,
        options: MessageOptions<'_>,
    ) -> Result<String> {
        Ok(self.generate(metadata::serialize(value, options, self.config.metadata)?))
    }

    /// Return `None` for invalid signatures, malformed envelopes, expiry, or purpose mismatch.
    /// JSON deserialization errors remain errors, as in ActiveSupport's `verified`.
    pub fn verified_json<T: DeserializeOwned>(
        &self,
        message: &str,
        options: VerifyOptions<'_>,
    ) -> Result<Option<T>> {
        match read_rotated(&self.config, &self.rotations, |config| {
            metadata::deserialize(&config.read(message)?, options)
        }) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.is_rejected() => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Strict JSON verification: invalid, expired, or purpose-mismatched tokens fail with
    /// `InvalidSignature`; JSON deserialization errors remain distinct.
    pub fn verify_json<T: DeserializeOwned>(
        &self,
        message: &str,
        options: VerifyOptions<'_>,
    ) -> Result<T> {
        self.verified_json(message, options)?
            .ok_or(Error::InvalidSignature)
    }
}
