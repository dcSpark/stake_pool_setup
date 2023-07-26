use crate::blockfrost::Blockfrost;
use crate::utxo_pointer::UtxoPointer;
use anyhow::anyhow;
use cardano_multiplatform_lib::address::{Address, EnterpriseAddress, StakeCredential};
use cardano_multiplatform_lib::builders::input_builder::SingleInputBuilder;
use cardano_multiplatform_lib::builders::output_builder::TransactionOutputBuilder;
use cardano_multiplatform_lib::builders::tx_builder::{
    TransactionBuilder, TransactionBuilderConfigBuilder,
};
use cardano_multiplatform_lib::ledger::alonzo::fees::LinearFee;
use cardano_multiplatform_lib::ledger::common::value::{BigNum, Coin, Int, Value};
use cardano_multiplatform_lib::plutus::{CostModel, Costmdls, ExUnitPrices, Language};
use cardano_multiplatform_lib::{
    AssetName, PolicyID, Transaction, TransactionInput, TransactionOutput, UnitInterval,
};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use crate::cip1852;
use crate::keys::Key;
use cardano_multiplatform_lib::crypto::PrivateKey;

pub async fn finalize_and_submit_tx(
    final_tx: Transaction,
    blockfrost: Blockfrost,
    submit: bool,
) -> anyhow::Result<()> {
    println!("Final tx: {}", hex::encode(final_tx.to_bytes()));

    if submit {
        println!(
            "Submitted tx: {:?}",
            blockfrost.v0_tx_submit(&final_tx).await??.to_hex()
        );
    }

    Ok(())
}

pub async fn fetch_inputs_and_balance_tx(
    tx_builder: &mut TransactionBuilder,
    inputs: &[UtxoPointer],
    blockfrost: &Blockfrost,
    payment_address: &Address,
    total_output: u64,
    total_input: u64,
) -> anyhow::Result<()> {
    println!("Fetching inputs");
    let mut total_input = Value::new(&Coin::from(total_input));
    for input in inputs {
        let utxo_balance = blockfrost
            .get_utxo_info(input.hash.to_string(), input.index)
            .await?
            .into_iter()
            .map(Value::from)
            .fold(Value::zero(), |acc, new| acc.checked_add(&new).unwrap());

        tx_builder
            .add_input(
                &SingleInputBuilder::new(
                    &TransactionInput::new(&input.hash, &BigNum::from(input.index)),
                    &TransactionOutput::new(payment_address, &utxo_balance),
                )
                .payment_key()
                .map_err(|err| anyhow!("Can't create tx input: {err:?}"))?,
            )
            .map_err(|err| anyhow!("Can't add tx input: {err:?}"))?;

        total_input = total_input.checked_add(&utxo_balance).unwrap();
    }

    let change_output = total_input
        .checked_sub(&Value::new(&Coin::from(total_output)))
        .unwrap();
    tx_builder
        .add_output(
            &TransactionOutputBuilder::new()
                .with_address(payment_address)
                .next()
                .map_err(|err| {
                    anyhow!("Can't create transaction output builder for change: {err:?}")
                })?
                .with_value(&change_output)
                .build()
                .map_err(|err| anyhow!("Can't build transaction output for change: {err:?}"))?,
        )
        .map_err(|err| anyhow!("Can't add transaction output for change: {err:?}"))?;

    Ok(())
}

pub fn create_tx_builder() -> TransactionBuilder {
    create_tx_builder_plutus(false)
}

pub fn create_tx_builder_plutus(include_plutus: bool) -> TransactionBuilder {
    let mut config = TransactionBuilderConfigBuilder::new()
        .max_tx_size(16384)
        .max_collateral_inputs(3)
        .collateral_percentage(150)
        .coins_per_utxo_byte(&Coin::from(4310))
        .key_deposit(&BigNum::from(2000000))
        .pool_deposit(&BigNum::from(500000000))
        .max_value_size(5000)
        .ex_unit_prices(&ExUnitPrices::new(
            &UnitInterval::new(&BigNum::from(577), &BigNum::from(10000)),
            &UnitInterval::new(&BigNum::from(721), &BigNum::from(10000000)),
        ))
        .fee_algo(&LinearFee::new(&Coin::from(44), &Coin::from(155381)));
    if include_plutus {
        let mut costmodels = Costmdls::new();
        let vasil_v2 = vec![
            205665, 812, 1, 1, 1000, 571, 0, 1, 1000, 24177, 4, 1, 1000, 32, 117366, 10475, 4,
            23000, 100, 23000, 100, 23000, 100, 23000, 100, 23000, 100, 23000, 100, 100, 100,
            23000, 100, 19537, 32, 175354, 32, 46417, 4, 221973, 511, 0, 1, 89141, 32, 497525,
            14068, 4, 2, 196500, 453240, 220, 0, 1, 1, 1000, 28662, 4, 2, 245000, 216773, 62, 1,
            1060367, 12586, 1, 208512, 421, 1, 187000, 1000, 52998, 1, 80436, 32, 43249, 32, 1000,
            32, 80556, 1, 57667, 4, 1000, 10, 197145, 156, 1, 197145, 156, 1, 204924, 473, 1,
            208896, 511, 1, 52467, 32, 64832, 32, 65493, 32, 22558, 32, 16563, 32, 76511, 32,
            196500, 453240, 220, 0, 1, 1, 69522, 11687, 0, 1, 60091, 32, 196500, 453240, 220, 0, 1,
            1, 196500, 453240, 220, 0, 1, 1, 1159724, 392670, 0, 2, 806990, 30482, 4, 1927926,
            82523, 4, 265318, 0, 4, 0, 85931, 32, 205665, 812, 1, 1, 41182, 32, 212342, 32, 31220,
            32, 32696, 32, 43357, 32, 32247, 32, 38314, 32, 35892428, 10, 57996947, 18975, 10,
            38887044, 32947, 10,
        ]
        .into_iter()
        .map(|integer| Int::new(&BigNum::from(integer)))
        .collect::<Vec<Int>>();

        costmodels.insert(&CostModel::new(&Language::new_plutus_v2(), &vasil_v2));
        config = config.costmdls(&costmodels);
    }
    let config = config.build().unwrap();

    TransactionBuilder::new(&config)
}

pub fn parse_asset(
    asset: &str,
) -> anyhow::Result<(cardano_multiplatform_lib::crypto::ScriptHash, AssetName)> {
    let asset = hex::decode(asset).map_err(|_| anyhow!("expected asset in hex"))?;
    let policy_id = asset[0..28].to_vec();
    let asset_name = asset[28..].to_vec();
    let asset_name = AssetName::new(asset_name).map_err(|_| anyhow!("invalid asset name"))?;
    let policy_id = PolicyID::from_bytes(policy_id).map_err(|_| anyhow!("invalid policy id"))?;
    Ok((policy_id, asset_name))
}

pub fn get_signing_creds(
    skey: Option<PathBuf>,
    mnemonics: Option<PathBuf>,
) -> anyhow::Result<PrivateKey> {
    if let Some(payment_address_sk) = skey {
        let payment_address_sk = Key::from_path(payment_address_sk)?;
        assert!(matches!(
            payment_address_sk,
            Key::PaymentSigningKeyShelley { .. }
        ));
        payment_address_sk.private_key()
    } else if let Some(mnemonics_path) = mnemonics {
        let mut buf = vec![];
        File::open(mnemonics_path)
            .map_err(|err| anyhow!("No mnemonics file found: {err}"))?
            .read_to_end(&mut buf)?;
        let mnemonics =
            String::from_utf8(buf).map_err(|err| anyhow!("Can't parse mnemonics {err}"))?;
        let root_key = cip1852::get_root_key(&mnemonics)?;
        let key = root_key.derive(cip1852::EXTERNAL).derive(0);
        Ok(key.to_raw_key())
    } else {
        Err(anyhow!("No payment signing credentials provided"))
    }
}

pub fn get_payment_creds(
    network: u8,
    vkey: Option<PathBuf>,
    bech32: Option<String>,
) -> anyhow::Result<Address> {
    if let Some(vkey) = vkey {
        let payment_address = Key::from_path(vkey)?;
        assert!(matches!(
            payment_address,
            Key::PaymentVerificationKeyShelley { .. }
        ));
        let payment_address_pk = payment_address.public_key()?;
        Ok(EnterpriseAddress::new(
            network,
            &StakeCredential::from_keyhash(&payment_address_pk.hash()),
        )
        .to_address())
    } else if let Some(pk) = bech32 {
        Ok(Address::from_bech32(&pk).map_err(|err| anyhow!("Can't parse bech32 pk: {err}"))?)
    } else {
        Err(anyhow!("No payment key provided"))
    }
}
