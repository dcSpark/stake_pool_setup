use crate::blockfrost::{Blockfrost, BlockfrostConfiguration};
use crate::keys::Key;
use crate::utils::{create_tx_builder, fetch_inputs_and_balance_tx, finalize_and_submit_tx};
use crate::utxo_pointer::UtxoPointer;
use anyhow::{anyhow, Context};
use cardano_multiplatform_lib::address::{Address, EnterpriseAddress, StakeCredential};
use cardano_multiplatform_lib::builders::mint_builder::SingleMintBuilder;
use cardano_multiplatform_lib::builders::output_builder::TransactionOutputBuilder;
use cardano_multiplatform_lib::builders::tx_builder::ChangeSelectionAlgo;
use cardano_multiplatform_lib::builders::witness_builder::NativeScriptWitnessInfo;
use cardano_multiplatform_lib::crypto::Vkeywitnesses;
use cardano_multiplatform_lib::ledger::common::hash::hash_transaction;
use cardano_multiplatform_lib::ledger::common::value::{BigNum, Coin, Int};
use cardano_multiplatform_lib::ledger::shelley::witness::make_vkey_witness;
use cardano_multiplatform_lib::metadata::AuxiliaryData;
use cardano_multiplatform_lib::{
    AssetName, Assets, MintAssets, MultiAsset, NativeScript, NativeScripts, ScriptAll,
    ScriptPubkey, TimelockExpiry, Transaction, TransactionWitnessSet,
};
use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;

#[derive(Parser)]
pub struct CreateNFT {
    config: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct CreateNFTConfiguration {
    pub minter_bech32: String,
    pub asset_name: String,
    pub lock_since: u64,
    pub send_to_bech32: String,

    pub inputs: Vec<UtxoPointer>,

    pub payment_vkey: PathBuf,
    pub payment_skey: PathBuf,
}

pub async fn handle_create_nft(
    config: CreateNFT,
    blockfrost: BlockfrostConfiguration,
    submit: bool,
) -> anyhow::Result<()> {
    let config: CreateNFTConfiguration = serde_yaml::from_reader(
        File::open(config.config).context("failed to open the create nft config file")?,
    )?;

    let network = blockfrost.get_network();
    println!("Network:\t{network}");

    let mut tx_builder = create_tx_builder();

    // create nfts
    let mut nfts = MintAssets::new();
    let asset_name = AssetName::new(config.asset_name.as_bytes().to_vec())
        .map_err(|err| anyhow!("Can't convert asset name: {}", err))?;
    nfts.insert(&asset_name, Int::from(1));

    let mint_builder = SingleMintBuilder::new(&nfts);
    let mut scripts = NativeScripts::new();
    scripts.add(&NativeScript::new_timelock_expiry(&TimelockExpiry::new(
        &BigNum::from(config.lock_since),
    )));

    let payment_address = Key::from_path(config.payment_vkey)?;
    assert!(matches!(
        payment_address,
        Key::PaymentVerificationKeyShelley { .. }
    ));
    let payment_address_pk = payment_address.public_key()?;
    let payment_address = EnterpriseAddress::new(
        network,
        &StakeCredential::from_keyhash(&payment_address_pk.hash()),
    )
    .to_address();
    println!(
        "Payment address:\t{}",
        payment_address
            .to_bech32(None)
            .map_err(|err| anyhow!("Can't display payment bech32: {err}"))?
    );
    println!(
        "Payment address:\t{}",
        hex::encode(payment_address_pk.as_bytes())
    );

    let minter_keyhash = payment_address_pk.hash();

    scripts.add(&NativeScript::new_timelock_expiry(&TimelockExpiry::new(
        &BigNum::from(config.lock_since),
    )));
    scripts.add(&NativeScript::new_script_pubkey(&ScriptPubkey::new(
        &minter_keyhash,
    )));
    let policy = NativeScript::new_script_all(&ScriptAll::new(&scripts));
    let mint =
        mint_builder.native_script(&policy, &NativeScriptWitnessInfo::assume_signature_count());
    tx_builder.add_mint(&mint);

    // add output for nft
    let send_to = Address::from_bech32(&config.send_to_bech32)
        .map_err(|err| anyhow!("Can't decode send to address: {err}"))?;

    let mut multiasset = MultiAsset::new();
    {
        let mut assets = Assets::new();

        let policy_id = policy.hash();
        assets.insert(&asset_name, &BigNum::from(1));
        multiasset.insert(&policy_id, &assets);
    }
    let nft_utxo_lovelace = 2000000;

    tx_builder
        .add_output(
            &TransactionOutputBuilder::new()
                .with_address(&send_to)
                .next()
                .map_err(|err| {
                    anyhow!("Can't create transaction output amount builder for NFT: {err}")
                })?
                .with_coin_and_asset(&Coin::from(nft_utxo_lovelace), &multiasset)
                .build()
                .map_err(|err| anyhow!("Can't create transaction output for NFT: {err}"))?,
        )
        .map_err(|err| anyhow!("Can't add transaction output for NFT: {err}"))?;

    let fee: u64 = 300000;
    tx_builder.set_fee(&Coin::from(fee));

    tx_builder.set_ttl(&BigNum::from(config.lock_since));

    let mut native_scripts = NativeScripts::new();
    native_scripts.add(&policy);
    let mut auxiliary_data = AuxiliaryData::new();
    auxiliary_data.set_native_scripts(&native_scripts);

    tx_builder.set_auxiliary_data(&auxiliary_data);
    let blockfrost = Blockfrost::new(blockfrost)?;
    fetch_inputs_and_balance_tx(
        &mut tx_builder,
        &config.inputs,
        &blockfrost,
        &payment_address,
        nft_utxo_lovelace + fee,
        0,
    )
    .await?;

    let signed_tx_builder = tx_builder
        .build(ChangeSelectionAlgo::Default, &payment_address)
        .map_err(|_err| anyhow!("Can't create tx body"))?;
    let body = signed_tx_builder.body();

    let signing_key = Key::from_path(config.payment_skey)?;
    assert!(matches!(signing_key, Key::PaymentSigningKeyShelley { .. }));
    let signing_key = signing_key.private_key()?;
    assert_eq!(signing_key.to_public(), payment_address_pk);

    let mut witness_set = TransactionWitnessSet::new();
    let mut witnesses = Vkeywitnesses::new();
    witnesses.add(&make_vkey_witness(&hash_transaction(&body), &signing_key));
    witness_set.set_vkeys(&witnesses);
    witness_set.set_native_scripts(&native_scripts);

    println!("inputs {:?}", body.inputs());
    println!("outputs {:?}", body.outputs());
    println!("fee {:?}", body.fee());

    let tx = Transaction::new(&body, &witness_set, Some(auxiliary_data)); //signed_tx_builder.build_unchecked();//.map_err(|err| anyhow!("can't build tx: {err:?}"))?;

    finalize_and_submit_tx(tx, blockfrost, submit).await
}
