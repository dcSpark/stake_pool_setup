use crate::blockfrost::{Blockfrost, BlockfrostConfiguration};
use crate::keys::Key;
use crate::utils::{create_tx_builder_plutus, fetch_inputs_and_balance_tx, finalize_and_submit_tx};
use crate::utxo_pointer::UtxoPointer;
use anyhow::{anyhow, Context};
use cardano_multiplatform_lib::address::{EnterpriseAddress, RewardAddress, StakeCredential};

use cardano_multiplatform_lib::builders::input_builder::SingleInputBuilder;

use cardano_multiplatform_lib::builders::output_builder::TransactionOutputBuilder;
use cardano_multiplatform_lib::builders::redeemer_builder::RedeemerWitnessKey;
use cardano_multiplatform_lib::builders::tx_builder::ChangeSelectionAlgo;
use cardano_multiplatform_lib::builders::withdrawal_builder::SingleWithdrawalBuilder;
use cardano_multiplatform_lib::builders::witness_builder::{
    PartialPlutusWitness, PlutusScriptWitness,
};
use cardano_multiplatform_lib::ledger::common::hash::hash_transaction;
use cardano_multiplatform_lib::ledger::common::value::{BigInt, BigNum, Coin, Value};
use cardano_multiplatform_lib::ledger::shelley::witness::make_vkey_witness;
use cardano_multiplatform_lib::plutus::{ExUnits, PlutusData, PlutusScript, RedeemerTag};
use cardano_multiplatform_lib::{
    AssetName, Assets, MultiAsset, PolicyID, RequiredSigners, TransactionInput, TransactionOutput,
};
use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
pub struct WithdrawRewards {
    config: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct WithdrawRewardsConfiguration {
    pub payment_vkey: PathBuf,
    pub payment_skey: PathBuf,

    pub rewards_address: PathBuf,

    pub inputs: Vec<UtxoPointer>,
    pub collateral: UtxoPointer,
    pub stake_nft_input: UtxoPointer,
    pub nft_policy_id_hex: String,
    pub nft_asset_name: String,
    pub withdraw_lovelace: u64,
}

pub async fn handle_withdraw_rewards(
    config: WithdrawRewards,
    blockfrost: BlockfrostConfiguration,
    submit: bool,
) -> anyhow::Result<()> {
    let config: WithdrawRewardsConfiguration = serde_yaml::from_reader(
        File::open(config.config).context("failed to open the delegate rewards config file")?,
    )?;

    let network = blockfrost.get_network();
    println!("Network:\t{network}");

    let reward_account_script = Key::from_path(config.rewards_address)?.plutus_script()?;
    let reward_account = RewardAddress::new(
        0,
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

    let payment_address_sk = Key::from_path(config.payment_skey)?;
    assert!(matches!(
        payment_address_sk,
        Key::PaymentSigningKeyShelley { .. }
    ));
    let payment_address_sk = payment_address_sk.private_key()?;

    let mut builder = create_tx_builder_plutus(true);

    let fee: u64 = 1808657;
    builder.set_fee(&Coin::from(fee));

    builder.add_required_signer(&payment_address_pk.hash());

    let blockfrost = Blockfrost::new(blockfrost)?;
    fetch_inputs_and_balance_tx(
        &mut builder,
        &config.inputs,
        &blockfrost,
        &payment_address,
        fee,
        config.withdraw_lovelace,
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

    builder
        .add_input(
            &SingleInputBuilder::new(
                &TransactionInput::new(
                    &config.stake_nft_input.hash,
                    &BigNum::from(config.stake_nft_input.index),
                ),
                &TransactionOutput::new(&payment_address, &nft_value),
            )
            .payment_key()
            .map_err(|_err| anyhow!("Can't create stake nft input"))?,
        )
        .map_err(|_err| anyhow!("Can't add stake nft input"))?;

    builder
        .add_output(
            &TransactionOutputBuilder::new()
                .with_address(&payment_address)
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

    builder.add_withdrawal(
        &SingleWithdrawalBuilder::new(&reward_account, &Coin::from(config.withdraw_lovelace))
            .plutus_script(
                &PartialPlutusWitness::new(
                    &PlutusScriptWitness::from_script(PlutusScript::from_v2(
                        &reward_account_script,
                    )),
                    &PlutusData::new_integer(&BigInt::from(42)),
                ),
                &RequiredSigners::new(),
            )
            .map_err(|err| anyhow!("Can't build withdrawal: {err:?}"))?,
    );

    let tx_redeemer_builder = builder
        .build_for_evaluation(ChangeSelectionAlgo::Default, &payment_address)
        .map_err(|err| anyhow!("Can't create tx body {err}"))?;
    let _redeemers = tx_redeemer_builder
        .build()
        .map_err(|_err| anyhow!("Can't build redeemers"))?;

    builder.set_exunits(
        &RedeemerWitnessKey::new(&RedeemerTag::new_reward(), &BigNum::from(0)),
        &ExUnits::new(&BigNum::from(14000000), &BigNum::from(10000000000)),
    );
    let mut signed_tx_builder = builder
        .build(ChangeSelectionAlgo::Default, &payment_address)
        .map_err(|err| anyhow!("Can't create tx body {err}"))?;
    let body = signed_tx_builder.body();

    signed_tx_builder.add_vkey(&make_vkey_witness(
        &hash_transaction(&body),
        &payment_address_sk,
    ));

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
