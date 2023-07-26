use anyhow::{anyhow, Context};
use cardano_multiplatform_lib::crypto::TransactionHash;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct UtxoPointer {
    pub hash: TransactionHash,
    pub index: u64,
}

impl Serialize for UtxoPointer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for UtxoPointer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        // do better hex decoding than this
        UtxoPointer::from_str(&s).map_err(|err| D::Error::custom(err.to_string()))
    }
}

impl std::str::FromStr for UtxoPointer {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hash, index) = s.split_once('@').ok_or_else(|| {
            anyhow!("UtxoPointer should be formatted as `<hex hash> '@' <index>`")
        })?;

        let hash = TransactionHash::from_bytes(hex::decode(hash).context("Invalid Hash format")?)
            .map_err(|error| anyhow!("Invalid hash format: {}", error))?;

        let index = u64::from_str(index).context("Invalid index format")?;

        Ok(UtxoPointer { hash, index })
    }
}

impl ToString for UtxoPointer {
    fn to_string(&self) -> String {
        format!("{}@{}", self.hash.to_hex(), self.index)
    }
}
