use crate::blockfrost::{Blockfrost, BlockfrostConfiguration};
use crate::keys::Key;
use crate::utils::{
    create_tx_builder, fetch_inputs_and_balance_tx, finalize_and_submit_tx, get_payment_creds,
    get_signing_creds,
};
use crate::utxo_pointer::UtxoPointer;
use anyhow::{anyhow, Context};
use cardano_multiplatform_lib::address::{RewardAddress, StakeCredential};
use cardano_multiplatform_lib::builders::certificate_builder::SingleCertificateBuilder;

use cardano_multiplatform_lib::builders::tx_builder::ChangeSelectionAlgo;

use cardano_multiplatform_lib::ledger::common::hash::hash_transaction;
use cardano_multiplatform_lib::ledger::common::value::Coin;
use cardano_multiplatform_lib::ledger::shelley::witness::make_vkey_witness;

use cardano_multiplatform_lib::{
    Certificate, StakeRegistration, Transaction, TransactionWitnessSet,
};
use clap::Parser;
use serde::Deserialize;
use std::fs::File;
use std::path::PathBuf;

#[derive(Parser)]
pub struct RegisterRewards {
    config: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct RegisterRewardsConfiguration {
    #[serde(default)]
    pub payment_vkey: Option<PathBuf>,
    #[serde(default)]
    pub payment_bech32: Option<String>,

    #[serde(default)]
    pub payment_mnemonics: Option<PathBuf>,
    #[serde(default)]
    pub payment_skey: Option<PathBuf>,

    pub rewards_address: PathBuf,

    pub inputs: Vec<UtxoPointer>,
}

pub async fn handle_register_rewards(
    config: RegisterRewards,
    blockfrost: BlockfrostConfiguration,
    submit: bool,
) -> anyhow::Result<()> {
    let config: RegisterRewardsConfiguration = serde_yaml::from_reader(
        File::open(config.config).context("failed to open the delegate rewards config file")?,
    )?;

    let network = blockfrost.get_network();
    println!("Network:\t{network}");

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

    let pool_rewards_stake_registration = StakeRegistration::new(
        &StakeCredential::from_scripthash(&reward_account_script.hash()),
    );
    let pool_rewards_stake_delegation_certificate =
        Certificate::new_stake_registration(&pool_rewards_stake_registration);

    let mut builder = create_tx_builder();

    let cert_builder = SingleCertificateBuilder::new(&pool_rewards_stake_delegation_certificate);
    builder.add_cert(&cert_builder.skip_witness());

    println!("required signers: {:?}", builder.required_signers());

    let payment_address = get_payment_creds(network, config.payment_vkey, config.payment_bech32)?;

    println!(
        "Payment address:\t{}",
        payment_address
            .to_bech32(None)
            .map_err(|err| anyhow!("Can't display payment bech32: {err}"))?
    );

    let fee: u64 = 200000;
    builder.set_fee(&Coin::from(fee));
    let reserve = 2000000;

    let blockfrost = Blockfrost::new(blockfrost)?;
    fetch_inputs_and_balance_tx(
        &mut builder,
        &config.inputs,
        &blockfrost,
        &payment_address,
        fee + reserve,
        0,
    )
    .await?;

    let mut signed_tx_builder = builder
        .build(ChangeSelectionAlgo::Default, &payment_address)
        .map_err(|_err| anyhow!("Can't create tx body"))?;
    let body = signed_tx_builder.body();

    if config.payment_skey.is_none() && config.payment_mnemonics.is_none() {
        println!("inputs {:?}", body.inputs());
        println!("outputs {:?}", body.outputs());
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

    println!("inputs {:?}", body.inputs());
    println!("outputs {:?}", body.outputs());
    println!("fee {:?}", body.fee());

    let tx = signed_tx_builder
        .build_checked()
        .map_err(|err| anyhow!("Can't build tx: {err}"))?;

    finalize_and_submit_tx(tx, blockfrost, submit).await
}
