use crate::{Digest, Error, Result};

/// ActiveSupport-compatible PBKDF2 key generation, independent of message encryption.
/// Defaults match standalone ActiveSupport (SHA1, 65,536 iterations).
#[derive(Clone)]
pub struct KeyGenerator {
    secret: Vec<u8>,
    digest: Digest,
    iterations: u32,
}

impl KeyGenerator {
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            secret: secret.as_ref().to_vec(),
            digest: Digest::Sha1,
            iterations: 65_536,
        }
    }

    /// Rails applications using defaults from 7.0 onward use SHA256 and 1,000 iterations.
    pub fn rails(secret: impl AsRef<[u8]>) -> Self {
        Self::new(secret).digest(Digest::Sha256).iterations(1000)
    }

    pub fn digest(mut self, digest: Digest) -> Self {
        self.digest = digest;
        self
    }

    pub fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// Derive exactly `length` bytes. Rails verifier keys commonly use 64 bytes;
    /// encryptor keys must match `Cipher::key_len()`.
    pub fn generate_key(&self, salt: impl AsRef<[u8]>, length: usize) -> Result<Vec<u8>> {
        if self.iterations == 0 || length == 0 {
            return Err(Error::InvalidKeyDerivation);
        }
        let mut output = vec![0; length];
        self.digest
            .derive(&self.secret, salt.as_ref(), self.iterations, &mut output);
        Ok(output)
    }
}
