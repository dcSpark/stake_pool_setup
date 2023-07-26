use crate::blockfrost::{Blockfrost, BlockfrostConfiguration};
use crate::keys::Key;
use crate::utils::{
    create_tx_builder_plutus, fetch_inputs_and_balance_tx, finalize_and_submit_tx,
    get_payment_creds, get_signing_creds,
};
use crate::utxo_pointer::UtxoPointer;
use anyhow::{anyhow, Context};
use cardano_multiplatform_lib::address::{RewardAddress, StakeCredential};
use cardano_multiplatform_lib::builders::certificate_builder::SingleCertificateBuilder;
use cardano_multiplatform_lib::builders::input_builder::SingleInputBuilder;

use cardano_multiplatform_lib::builders::output_builder::TransactionOutputBuilder;
use cardano_multiplatform_lib::builders::redeemer_builder::RedeemerWitnessKey;
use cardano_multiplatform_lib::builders::tx_builder::ChangeSelectionAlgo;
use cardano_multiplatform_lib::builders::witness_builder::{
    PartialPlutusWitness, PlutusScriptWitness,
};
use cardano_multiplatform_lib::ledger::common::hash::hash_transaction;
use cardano_multiplatform_lib::ledger::common::value::{BigInt, BigNum, Coin, Value};
use cardano_multiplatform_lib::ledger::shelley::witness::make_vkey_witness;
use cardano_multiplatform_lib::plutus::{ExUnits, PlutusData, PlutusScript, RedeemerTag};
use cardano_multiplatform_lib::{
    AssetName, Assets, Certificate, MultiAsset, PolicyID, RequiredSigners, StakeDelegation,
    Transaction, TransactionInput, TransactionOutput, TransactionWitnessSet,
};
use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
pub struct DelegateRewards {
    config: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct DelegateRewardsConfiguration {
    pub cold_vkey: PathBuf,

    pub payment_vkey: Option<PathBuf>,
    pub payment_bech32: Option<String>,

    pub payment_mnemonics: Option<PathBuf>,
    pub payment_skey: Option<PathBuf>,

    pub rewards_address: PathBuf,

    pub inputs: Vec<UtxoPointer>,
    pub collateral: UtxoPointer,

    pub stake_nft_input: UtxoPointer,

    #[serde(default)]
    pub use_same_address_for_nft: bool,

    pub stake_nft_vkey: Option<PathBuf>,
    pub stake_nft_bech32: Option<String>,

    pub stake_nft_mnemonics: Option<PathBuf>,
    pub stake_nft_skey: Option<PathBuf>,

    pub nft_policy_id_hex: String,
    pub nft_asset_name: String,
}

pub async fn handle_delegate_rewards(
    config: DelegateRewards,
    blockfrost: BlockfrostConfiguration,
    submit: bool,
) -> anyhow::Result<()> {
    let config: DelegateRewardsConfiguration = serde_yaml::from_reader(
        File::open(config.config).context("failed to open the delegate rewards config file")?,
    )?;

    let network = blockfrost.get_network();
    println!("Network:\t{network}");

    // cold
    let cold_vkey_operator = Key::from_path(config.cold_vkey)?;
    assert!(matches!(
        cold_vkey_operator,
        Key::StakePoolVerificationKey { .. }
    ));
    let cold_vkey_operator = cold_vkey_operator.public_key()?;
    println!("cold_vkey:\t{}", hex::encode(cold_vkey_operator.as_bytes()));

    let reward_account_script = Key::from_path(config.rewards_address)?.plutus_script()?;
    let reward_account = RewardAddress::new(
        network,
        &StakeCredential::from_scripthash(&reward_account_script.hash()),
    );
    println!(
        "rewards bech32:\t{}",
        reward_account.to_address().to_bech32(None).unwrap()
    );
    println!(
        "rewards hex:\t{}",
        hex::encode(reward_account.to_address().to_bytes())
    );

    let pool_rewards_stake_delegation = StakeDelegation::new(
        &StakeCredential::from_scripthash(
            &reward_account
                .payment_cred()
                .to_scripthash()
                .ok_or(anyhow!("Rewards address is not a scripthash"))?,
        ),
        &cold_vkey_operator.hash(),
    );
    let pool_rewards_stake_delegation_certificate =
        Certificate::new_stake_delegation(&pool_rewards_stake_delegation);

    let mut builder = create_tx_builder_plutus(true);

    let cert_builder = SingleCertificateBuilder::new(&pool_rewards_stake_delegation_certificate);
    builder.add_cert(
        &cert_builder
            .plutus_script(
                &PartialPlutusWitness::new(
                    &PlutusScriptWitness::from_script(PlutusScript::from_v2(
                        &reward_account_script,
                    )),
                    &PlutusData::new_integer(&BigInt::from(42)),
                ),
                &RequiredSigners::new(),
            )
            .map_err(|err| anyhow!("can't build plutus script witness {err}"))?,
    );

    let payment_address = get_payment_creds(network, config.payment_vkey, config.payment_bech32)?;

    println!(
        "Payment address:\t{}",
        payment_address
            .to_bech32(None)
            .map_err(|err| anyhow!("Can't display payment bech32: {err}"))?
    );

    let fee: u64 = 1900000;
    builder.set_fee(&Coin::from(fee));

    let blockfrost = Blockfrost::new(blockfrost)?;
    fetch_inputs_and_balance_tx(
        &mut builder,
        &config.inputs,
        &blockfrost,
        &payment_address,
        fee,
        0,
    )
    .await?;

    let collateral_balance: u64 = blockfrost
        .get_utxo_info(config.collateral.hash.to_string(), config.collateral.index)
        .await?
        .into_iter()
        .filter(|asset_amount| asset_amount.unit == "lovelace")
        .map(|asset_amount| u64::from_str(&asset_amount.quantity).unwrap_or(0))
        .sum();

    let stake_nft_balance: u64 = blockfrost
        .get_utxo_info(
            config.stake_nft_input.hash.to_string(),
            config.stake_nft_input.index,
        )
        .await?
        .into_iter()
        .filter(|asset_amount| asset_amount.unit == "lovelace")
        .map(|asset_amount| u64::from_str(&asset_amount.quantity).unwrap_or(0))
        .sum();

    let mut nft_value = Value::new(&Coin::from(stake_nft_balance));
    let mut nft_multiasset = MultiAsset::new();
    let mut assets = Assets::new();
    assets.insert(
        &AssetName::new(config.nft_asset_name.as_bytes().to_vec())
            .map_err(|err| anyhow!("Can't decode asset name: {err:?}"))?,
        &BigNum::from(1),
    );
    nft_multiasset.insert(
        &PolicyID::from_hex(&config.nft_policy_id_hex)
            .map_err(|err| anyhow!("Can't decode policy: {err:?}"))?,
        &assets,
    );
    nft_value.set_multiasset(&nft_multiasset);

    let stake_nft_address = if config.use_same_address_for_nft {
        payment_address.clone()
    } else {
        get_payment_creds(network, config.stake_nft_vkey, config.stake_nft_bech32)?
    };

    builder
        .add_input(
            &SingleInputBuilder::new(
                &TransactionInput::new(
                    &config.stake_nft_input.hash,
                    &BigNum::from(config.stake_nft_input.index),
                ),
                &TransactionOutput::new(&stake_nft_address, &nft_value),
            )
            .payment_key()
            .map_err(|_err| anyhow!("Can't create stake nft input"))?,
        )
        .map_err(|_err| anyhow!("Can't add stake nft input"))?;

    builder
        .add_output(
            &TransactionOutputBuilder::new()
                .with_address(&stake_nft_address)
                .next()
                .map_err(|err| {
                    anyhow!("Can't create transaction output amount builder for nft {err:?}")
                })?
                .with_coin_and_asset(&Coin::from(stake_nft_balance), &nft_multiasset)
                .build()
                .map_err(|err| anyhow!("can't create nft output {err:?}"))?,
        )
        .map_err(|err| anyhow!("can't add nft output {err:?}"))?;

    builder
        .add_collateral(
            &SingleInputBuilder::new(
                &TransactionInput::new(
                    &config.collateral.hash,
                    &BigNum::from(config.collateral.index),
                ),
                &TransactionOutput::new(
                    &payment_address,
                    &Value::new(&Coin::from(collateral_balance)),
                ),
            )
            .payment_key()
            .map_err(|_err| anyhow!("Can't create collateral input"))?,
        )
        .map_err(|_err| anyhow!("Can't add collateral input"))?;
    builder.set_collateral_return(&TransactionOutput::new(
        &payment_address,
        &Value::new(&Coin::from(collateral_balance - 4000000)),
    ));

    builder.set_exunits(
        &RedeemerWitnessKey::new(&RedeemerTag::new_cert(), &BigNum::from(0)),
        &ExUnits::new(&BigNum::from(14000000), &BigNum::from(10000000000)),
    );
    let mut signed_tx_builder = builder
        .build(ChangeSelectionAlgo::Default, &payment_address)
        .map_err(|err| anyhow!("Can't create tx body {err}"))?;
    let body = signed_tx_builder.body();

    if config.payment_skey.is_none() && config.payment_mnemonics.is_none() {
        println!("inputs {:?}", body.inputs());
        println!("outputs {:?}", body.outputs());
        println!("collateral {:?}", body.collateral());
        println!("collateral return {:?}", body.collateral_return());
        println!("fee {:?}", body.fee());

        println!(
            "body: {}",
            hex::encode(Transaction::new(&body, &TransactionWitnessSet::new(), None).to_bytes())
        );
        return Ok(());
    }

    let payment_address_sk = get_signing_creds(config.payment_skey, config.payment_mnemonics)?;

    signed_tx_builder.add_vkey(&make_vkey_witness(
        &hash_transaction(&body),
        &payment_address_sk,
    ));

    if !config.use_same_address_for_nft {
        let payment_address_sk =
            get_signing_creds(config.stake_nft_skey, config.stake_nft_mnemonics)?;

        signed_tx_builder.add_vkey(&make_vkey_witness(
            &hash_transaction(&body),
            &payment_address_sk,
        ));
    }

    let tx = signed_tx_builder
        .build_checked()
        .map_err(|err| anyhow!("Can't build tx: {err}"))?;

    println!("inputs {:?}", body.inputs());
    println!("outputs {:?}", body.outputs());
    println!("collateral {:?}", body.collateral());
    println!("collateral return {:?}", body.collateral_return());
    println!("fee {:?}", body.fee());

    finalize_and_submit_tx(tx, blockfrost, submit).await
}
