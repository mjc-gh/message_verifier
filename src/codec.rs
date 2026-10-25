use base64::{
    alphabet,
    engine::{general_purpose, GeneralPurpose, GeneralPurposeConfig},
    Engine,
};

use crate::{Error, Result};

/// Standard padded Base64 or Rails' unpadded URL-safe Base64.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Encoding {
    #[default]
    Standard,
    UrlSafe,
}

impl Encoding {
    pub(crate) fn encode(self, data: impl AsRef<[u8]>) -> String {
        match self {
            Self::Standard => general_purpose::STANDARD.encode(data),
            Self::UrlSafe => general_purpose::URL_SAFE_NO_PAD.encode(data),
        }
    }

    pub(crate) fn decode(self, data: &str) -> Result<Vec<u8>> {
        let result = match self {
            Self::Standard => general_purpose::STANDARD.decode(data),
            Self::UrlSafe => {
                // Ruby's urlsafe_decode64 also accepts correctly padded input.
                let config = GeneralPurposeConfig::new()
                    .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);
                GeneralPurpose::new(&alphabet::URL_SAFE, config).decode(data)
            }
        };
        result.map_err(|_| Error::InvalidMessage)
    }

    pub(crate) fn encoded_len(self, bytes: usize) -> usize {
        match self {
            Self::Standard => bytes.div_ceil(3) * 4,
            Self::UrlSafe => (bytes * 4).div_ceil(3),
        }
    }
}

/// Extract a fixed-length suffix without treating `--` inside Base64 as a delimiter.
pub(crate) fn extract_part(message: &str, length: usize) -> Result<(&str, &str)> {
    let index = message
        .len()
        .checked_sub(length + 2)
        .ok_or(Error::InvalidMessage)?;
    let prefix = message.get(..index).ok_or(Error::InvalidMessage)?;
    if message.get(index..index + 2) != Some("--") {
        return Err(Error::InvalidMessage);
    }
    let part = message.get(index + 2..).ok_or(Error::InvalidMessage)?;
    Ok((prefix, part))
}

pub(crate) fn read_rotated<C, T>(
    primary: &C,
    rotations: &[C],
    mut read: impl FnMut(&C) -> Result<T>,
) -> Result<T> {
    let original = match read(primary) {
        Ok(value) => return Ok(value),
        Err(error) if error.is_content() => return Err(error),
        Err(error) => error,
    };
    for rotation in rotations {
        match read(rotation) {
            Ok(value) => return Ok(value),
            Err(error) if error.is_content() => return Err(error),
            Err(_) => (),
        }
    }
    Err(original)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_never_continues_after_content_rejection() {
        for rejection_at in 0..3 {
            let mut attempts = 0;
            let result: Result<()> = read_rotated(&0, &[1, 2, 3], |config| {
                attempts += 1;
                if *config == rejection_at {
                    Err(Error::Expired)
                } else {
                    Err(Error::InvalidMessage)
                }
            });
            assert!(matches!(result, Err(Error::Expired)));
            assert_eq!(attempts, rejection_at + 1);
        }
    }
}
