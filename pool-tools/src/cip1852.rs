use anyhow::Context;
use cardano_multiplatform_lib::crypto::Bip32PrivateKey;

pub const HARD_DERIVATION_START: u32 = 0x80000000;
pub const PURPOSE: u32 = HARD_DERIVATION_START + 1852;
pub const COIN_TYPE: u32 = HARD_DERIVATION_START + 1815;
pub const DEFAULT_ACCOUNT: u32 = HARD_DERIVATION_START;
pub const EXTERNAL: u32 = 0;

pub fn get_root_key(mnemonic: &str) -> Result<Bip32PrivateKey, anyhow::Error> {
    let mnemonic: bip39::Mnemonic = mnemonic.parse().context("invalid mnemonics")?;
    let root_key = Bip32PrivateKey::from_bip39_entropy(&mnemonic.to_entropy(), &[])
        .derive(PURPOSE)
        .derive(COIN_TYPE)
        .derive(DEFAULT_ACCOUNT);

    Ok(root_key)
}
