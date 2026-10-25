use pbkdf2::{
    hmac::{Hmac, KeyInit, Mac},
    pbkdf2_hmac,
};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

/// HMAC and PBKDF2 digest algorithms supported by ActiveSupport.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Digest {
    #[default]
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Digest {
    pub(crate) fn hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
            Self::Sha384 => 96,
            Self::Sha512 => 128,
        }
    }

    pub(crate) fn sign(self, key: &[u8], data: &[u8]) -> String {
        macro_rules! sign {
            ($hash:ty) => {{
                // HMAC accepts keys of any size.
                let mut mac =
                    Hmac::<$hash>::new_from_slice(key).expect("HMAC accepts any key length");
                mac.update(data);
                hex::encode(mac.finalize().into_bytes())
            }};
        }
        match self {
            Self::Sha1 => sign!(Sha1),
            Self::Sha256 => sign!(Sha256),
            Self::Sha384 => sign!(Sha384),
            Self::Sha512 => sign!(Sha512),
        }
    }

    pub(crate) fn verify(self, key: &[u8], data: &[u8], signature: &str) -> bool {
        // Rails compares lowercase hexadecimal HMACs, not arbitrary hex encodings.
        if signature.len() != self.hex_len()
            || !signature
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return false;
        }
        let Ok(signature) = hex::decode(signature) else {
            return false;
        };
        macro_rules! verify {
            ($hash:ty) => {{
                let mut mac =
                    Hmac::<$hash>::new_from_slice(key).expect("HMAC accepts any key length");
                mac.update(data);
                mac.verify_slice(&signature).is_ok()
            }};
        }
        match self {
            Self::Sha1 => verify!(Sha1),
            Self::Sha256 => verify!(Sha256),
            Self::Sha384 => verify!(Sha384),
            Self::Sha512 => verify!(Sha512),
        }
    }

    pub(crate) fn derive(self, secret: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
        match self {
            Self::Sha1 => pbkdf2_hmac::<Sha1>(secret, salt, iterations, output),
            Self::Sha256 => pbkdf2_hmac::<Sha256>(secret, salt, iterations, output),
            Self::Sha384 => pbkdf2_hmac::<Sha384>(secret, salt, iterations, output),
            Self::Sha512 => pbkdf2_hmac::<Sha512>(secret, salt, iterations, output),
        }
    }
}
