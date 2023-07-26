use crate::blockfrost::{Blockfrost, BlockfrostConfiguration};
use crate::utils::finalize_and_submit_tx;
use anyhow::anyhow;
use cardano_multiplatform_lib::Transaction;
use clap::Parser;

#[derive(Parser)]
pub struct SendTransaction {
    cbor_hex: String,
}

pub async fn handle_send_tx(
    config: SendTransaction,
    blockfrost: BlockfrostConfiguration,
) -> anyhow::Result<()> {
    let tx = Transaction::from_bytes(
        hex::decode(config.cbor_hex).map_err(|err| anyhow!("Can't decode tx hex: {err}"))?,
    )
    .map_err(|err| anyhow!("Can't decode tx: {err}"))?;
    let blockfrost = Blockfrost::new(blockfrost)?;
    finalize_and_submit_tx(tx, blockfrost, true).await
}
