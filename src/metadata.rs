use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{de::DeserializeOwned, Serialize};
use serde_json::{Map, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{Encoding, Error, Result};

/// JSON metadata format used when generating messages with a purpose or expiration.
/// Both formats are accepted when reading JSON messages.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MetadataFormat {
    /// Rails 7.1+ with `use_message_serializer_for_metadata = true` and a JSON serializer.
    #[default]
    Current,
    /// Rails <= 7.0 or `force_legacy_metadata_serializer: true`.
    Legacy,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MessageOptions<'a> {
    pub purpose: Option<&'a str>,
    pub expires_at: Option<SystemTime>,
    pub expires_in: Option<Duration>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct VerifyOptions<'a> {
    pub purpose: Option<&'a str>,
    /// Override the clock for deterministic expiration checks; defaults to `SystemTime::now()`.
    pub now: Option<SystemTime>,
}

fn datetime(time: SystemTime) -> Result<OffsetDateTime> {
    let nanos = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as i128,
        Err(error) => -(error.duration().as_nanos() as i128),
    };
    OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| Error::InvalidTimestamp)
}

pub(crate) fn serialize<T: Serialize + ?Sized>(
    value: &T,
    options: MessageOptions<'_>,
    format: MetadataFormat,
) -> Result<Vec<u8>> {
    if options.purpose.is_none() && options.expires_at.is_none() && options.expires_in.is_none() {
        return Ok(serde_json::to_vec(value)?);
    }
    let expiry = match options.expires_at {
        Some(expiry) => Some(expiry),
        None => options
            .expires_in
            .map(|duration| {
                SystemTime::now()
                    .checked_add(duration)
                    .ok_or(Error::InvalidTimestamp)
            })
            .transpose()?,
    };
    let mut metadata = Map::new();
    if format == MetadataFormat::Legacy {
        metadata.insert(
            "message".into(),
            Encoding::Standard.encode(serde_json::to_vec(value)?).into(),
        );
    } else {
        metadata.insert("data".into(), serde_json::to_value(value)?);
    }
    if let Some(expiry) = expiry {
        // Rails uses UTC ISO8601 with exactly three fractional digits.
        let expiry = datetime(expiry)?;
        let description = time::format_description::parse_borrowed::<2>(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z",
        )
        .map_err(|_| Error::InvalidTimestamp)?;
        let expiry = expiry
            .format(&description)
            .map_err(|_| Error::InvalidTimestamp)?;
        metadata.insert("exp".into(), expiry.into());
    } else if format == MetadataFormat::Legacy {
        metadata.insert("exp".into(), Value::Null);
    }
    if let Some(purpose) = options.purpose {
        metadata.insert("pur".into(), purpose.into());
    } else if format == MetadataFormat::Legacy {
        metadata.insert("pur".into(), Value::Null);
    }
    let mut envelope = Map::new();
    envelope.insert("_rails".into(), Value::Object(metadata));
    Ok(serde_json::to_vec(&envelope)?)
}

pub(crate) fn deserialize<T: DeserializeOwned>(
    data: &[u8],
    options: VerifyOptions<'_>,
) -> Result<T> {
    // Rails recognizes this exact prefix before deserializing legacy envelopes.
    // A broken outer envelope is a format failure, not an incompatible serializer.
    let legacy = data.starts_with(b"{\"_rails\":{\"message\":");
    let mut value: Value = serde_json::from_slice(data).map_err(|error| {
        if legacy {
            Error::InvalidMessage
        } else {
            Error::Serialization(error)
        }
    })?;
    if let Some(envelope) = value
        .as_object_mut()
        .and_then(|object| object.remove("_rails"))
    {
        let envelope = envelope.as_object().ok_or(Error::InvalidMessage)?;
        if let Some(expiry) = envelope.get("exp").filter(|value| !value.is_null()) {
            let expiry = expiry.as_str().ok_or(Error::InvalidMessage)?;
            let expiry =
                OffsetDateTime::parse(expiry, &Rfc3339).map_err(|_| Error::InvalidMessage)?;
            if datetime(options.now.unwrap_or_else(SystemTime::now))? >= expiry {
                return Err(Error::Expired);
            }
        }
        let purpose = match envelope.get("pur") {
            None | Some(Value::Null) => "",
            Some(Value::String(purpose)) => purpose,
            _ => return Err(Error::InvalidMessage),
        };
        if purpose != options.purpose.unwrap_or("") {
            return Err(Error::PurposeMismatch);
        }
        if legacy {
            let message = envelope.get("message").ok_or(Error::InvalidMessage)?;
            let message = message.as_str().ok_or(Error::InvalidMessage)?;
            let data = Encoding::Standard.decode(message)?;
            return Ok(serde_json::from_slice(&data)?);
        }
        value = envelope.get("data").cloned().ok_or(Error::InvalidMessage)?;
    } else if options.purpose.is_some() {
        return Err(Error::PurposeMismatch);
    }
    Ok(serde_json::from_value(value)?)
}
