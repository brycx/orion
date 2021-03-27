use crate::{auth, hash, kdf, pwhash::PasswordHash};
use serde::{
    de::{self, Deserialize, Deserializer},
    ser::{Serialize, Serializer},
};

impl Serialize for PasswordHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded_string = self.unprotected_as_encoded();
        serializer.serialize_str(&encoded_string)
    }
}

impl<'de> Deserialize<'de> for PasswordHash {
    fn deserialize<D>(deserializer: D) -> Result<PasswordHash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded_str = <&str>::deserialize(deserializer)?;
        PasswordHash::from_encoded(encoded_str).map_err(de::Error::custom)
    }
}

impl Serialize for hash::Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: &[u8] = self.as_ref();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for hash::Digest {
    fn deserialize<D>(deserializer: D) -> Result<hash::Digest, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <&[u8]>::deserialize(deserializer)?;
        hash::Digest::from_slice(bytes).map_err(de::Error::custom)
    }
}

impl Serialize for auth::Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: &[u8] = self.unprotected_as_bytes();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for auth::Tag {
    fn deserialize<D>(deserializer: D) -> Result<auth::Tag, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <&[u8]>::deserialize(deserializer)?;
        auth::Tag::from_slice(bytes).map_err(de::Error::custom)
    }
}

impl Serialize for kdf::Salt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: &[u8] = self.as_ref();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for kdf::Salt {
    fn deserialize<D>(deserializer: D) -> Result<kdf::Salt, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <&[u8]>::deserialize(deserializer)?;
        kdf::Salt::from_slice(bytes).map_err(de::Error::custom)
    }
}
