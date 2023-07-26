use anyhow::{anyhow, bail, Context};
use cardano_multiplatform_lib::crypto::{VRFKeyHash, VRFVKey};

use cryptoxide::blake2b::Blake2b;

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::hash::Hash;
use std::io::Cursor;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
#[allow(clippy::enum_variant_names)]
pub enum Key {
    #[serde(rename = "StakePoolVerificationKey_ed25519")]
    StakePoolVerificationKey(StakePoolVerificationKey),
    #[serde(rename = "StakePoolSigningKey_ed25519")]
    StakePoolSigningKey(StakePoolSigningKey),
    #[serde(rename = "StakeVerificationKeyShelley_ed25519")]
    StakeVerificationKeyShelley(StakeVerificationKeyShelley),
    #[serde(rename = "StakeSigningKeyShelley_ed25519")]
    StakeSigningKeyShelley(StakeSigningKeyShelley),
    #[serde(rename = "VrfVerificationKey_PraosVRF")]
    VrfVerificationKey(VrfVerificationKey),
    #[serde(rename = "VrfSigningKey_PraosVRF")]
    VrfSigningKey(VrfSigningKey),
    #[serde(rename = "PaymentVerificationKeyShelley_ed25519")]
    PaymentVerificationKeyShelley(PaymentVerificationKeyShelley),
    #[serde(rename = "PaymentSigningKeyShelley_ed25519")]
    PaymentSigningKeyShelley(PaymentSigningKeyShelley),
    PlutusScriptV2(PlutusScriptV2),
}

impl Key {
    pub fn from_path(path: PathBuf) -> anyhow::Result<Self> {
        serde_json::from_reader(
            File::open(path.clone())
                .context(format!("failed to open the key config file: {path:?}"))?,
        )
        .map_err(|err| anyhow!("Can't deserialize key: {err}"))
    }

    pub fn public_key(self) -> anyhow::Result<cardano_multiplatform_lib::crypto::PublicKey> {
        let bytes = match self {
            Key::StakePoolVerificationKey(key) => hex::decode(key.cbor_hex)?,
            Key::StakeVerificationKeyShelley(key) => hex::decode(key.cbor_hex)?,
            Key::VrfVerificationKey(key) => hex::decode(key.cbor_hex)?,
            Key::PaymentVerificationKeyShelley(key) => hex::decode(key.cbor_hex)?,
            _ => bail!("Can't convert {self:?} to PublicKey"),
        };
        let mut deserializer = cbor_event::de::Deserializer::from(Cursor::new(bytes));
        let (bytes, _len) = deserializer.bytes_sz()?;
        cardano_multiplatform_lib::crypto::PublicKey::from_bytes(&bytes)
            .map_err(|err| anyhow!("Can't decode PublicKey: {err}"))
    }

    pub fn private_key(self) -> anyhow::Result<cardano_multiplatform_lib::crypto::PrivateKey> {
        let bytes = match self {
            Key::StakePoolSigningKey(key) => hex::decode(key.cbor_hex)?,
            Key::StakeSigningKeyShelley(key) => hex::decode(key.cbor_hex)?,
            Key::VrfSigningKey(key) => hex::decode(key.cbor_hex)?,
            Key::PaymentSigningKeyShelley(key) => hex::decode(key.cbor_hex)?,
            _ => bail!("Can't convert {self:?} to PrivateKey"),
        };
        let mut deserializer = cbor_event::de::Deserializer::from(Cursor::new(bytes));
        let (bytes, _len) = deserializer.bytes_sz()?;
        cardano_multiplatform_lib::crypto::PrivateKey::from_normal_bytes(&bytes)
            .map_err(|err| anyhow!("Can't decode PrivateKey: {err}"))
    }

    pub fn plutus_script(
        self,
    ) -> anyhow::Result<cardano_multiplatform_lib::plutus::PlutusV2Script> {
        let bytes = match self {
            Key::PlutusScriptV2(key) => hex::decode(key.cbor_hex)?,
            _ => bail!("Can't convert {self:?} to PublicKey"),
        };
        // let mut deserializer = cbor_event::de::Deserializer::from(Cursor::new(bytes));
        // let (bytes, len) = deserializer.bytes_sz()?;
        cardano_multiplatform_lib::plutus::PlutusV2Script::from_bytes(bytes)
            .map_err(|err| anyhow!("Can't decode plutus script: {err}"))
    }

    pub fn vrf_vkey(self) -> anyhow::Result<cardano_multiplatform_lib::crypto::VRFVKey> {
        let bytes = match self {
            Key::VrfVerificationKey(key) => hex::decode(key.cbor_hex)?,
            _ => bail!("Only VrfVerificationKey can be converted to VRFVKey, while got: {self:?}"),
        };

        let mut deserializer = cbor_event::de::Deserializer::from(Cursor::new(bytes));
        let (bytes, _len) = deserializer.bytes_sz()?;
        VRFVKey::from_bytes(bytes).map_err(|err| anyhow!("Can't decode VRFVKey: {err}"))
    }

    pub fn vrf_vkeyhash(self) -> anyhow::Result<cardano_multiplatform_lib::crypto::VRFKeyHash> {
        let vrf_key = self.vrf_vkey()?;
        let bytes = vrf_key.to_bytes();

        let mut out = [0; 32];
        Blake2b::blake2b(&mut out, &bytes, &[]);

        VRFKeyHash::from_bytes(out.to_vec())
            .map_err(|err| anyhow!("Can't decode VRFKeyHash: {err}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub struct StakePoolVerificationKey {
    description: String,
    cbor_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub struct StakePoolSigningKey {
    description: String,
    cbor_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub struct StakeVerificationKeyShelley {
    description: String,
    cbor_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub struct StakeSigningKeyShelley {
    description: String,
    cbor_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub struct VrfVerificationKey {
    description: String,
    cbor_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub struct VrfSigningKey {
    description: String,
    cbor_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub struct PaymentVerificationKeyShelley {
    description: String,
    cbor_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub struct PaymentSigningKeyShelley {
    description: String,
    cbor_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub struct PlutusScriptV2 {
    description: String,
    cbor_hex: String,
}
