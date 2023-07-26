use crate::blockfrost::{Blockfrost, BlockfrostConfiguration};
use crate::keys::Key;
use crate::utils::{
    create_tx_builder, fetch_inputs_and_balance_tx, finalize_and_submit_tx, get_payment_creds,
};
use crate::utxo_pointer::UtxoPointer;
use anyhow::{anyhow, Context};
use cardano_multiplatform_lib::address::{RewardAddress, StakeCredential};
use cardano_multiplatform_lib::builders::certificate_builder::SingleCertificateBuilder;
use cardano_multiplatform_lib::builders::tx_builder::ChangeSelectionAlgo;
use cardano_multiplatform_lib::crypto::PoolMetadataHash;
use cardano_multiplatform_lib::ledger::common::hash::hash_transaction;
use cardano_multiplatform_lib::ledger::common::value::{BigNum, Coin};
use cardano_multiplatform_lib::ledger::shelley::witness::make_vkey_witness;
use cardano_multiplatform_lib::{
    Certificate, Ed25519KeyHashes, PoolMetadata, PoolParams, PoolRegistration, Relays, Transaction,
    TransactionWitnessSet, UnitInterval, URL,
};
use clap::Parser;
use cryptoxide::hashing::blake2b_256;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
pub struct IssueRegistrationCeritifcate {
    config: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct IssueRegistrationCeritifcateConfiguration {
    pub cold_vkey: PathBuf,
    pub cold_skey: Option<PathBuf>,
    pub stake_vkey: PathBuf,
    pub stake_skey: Option<PathBuf>,
    pub vrf_vkey: PathBuf,
    pub payment_vkey: Option<PathBuf>,
    pub payment_bech32: Option<String>,
    pub payment_skey: Option<PathBuf>,

    pub rewards_address: PathBuf,
    pub pool_metadata: PathBuf,
    pub pool_metadata_url: URL,

    pub pledge: BigNum,
    pub cost: BigNum,
    pub margin_numerator: BigNum,
    pub margin_denominator: BigNum,
    pub relays: Relays,

    pub inputs: Vec<UtxoPointer>,
}

pub async fn handle_issue_reg_cert(
    reg: IssueRegistrationCeritifcate,
    blockfrost: BlockfrostConfiguration,
    submit: bool,
) -> anyhow::Result<()> {
    let reg: IssueRegistrationCeritifcateConfiguration = serde_yaml::from_reader(
        File::open(reg.config)
            .context("failed to open the registration certificate config file")?,
    )?;

    let network = blockfrost.get_network();
    println!("Network:\t{network}");

    // cold
    let cold_vkey_operator = Key::from_path(reg.cold_vkey)?;
    assert!(matches!(
        cold_vkey_operator,
        Key::StakePoolVerificationKey { .. }
    ));
    let cold_vkey_operator = cold_vkey_operator.public_key()?;
    println!("cold_vkey:\t{}", hex::encode(cold_vkey_operator.as_bytes()));

    // owner
    let stake_vkey_operator = Key::from_path(reg.stake_vkey)?;
    assert!(matches!(
        stake_vkey_operator,
        Key::StakeVerificationKeyShelley { .. }
    ));
    let stake_vkey_operator = stake_vkey_operator.public_key()?;
    println!(
        "stake_vkey:\t{}",
        hex::encode(stake_vkey_operator.as_bytes())
    );

    // vrf
    let vrf_vkey = Key::from_path(reg.vrf_vkey)?;
    assert!(matches!(vrf_vkey, Key::VrfVerificationKey { .. }));
    let vrf_vkey_hash = vrf_vkey.clone().vrf_vkeyhash()?;
    println!("vrf_vkey_hash:\t{}", hex::encode(vrf_vkey_hash.to_bytes()));

    let pledge = reg.pledge;
    println!("pledge:\t{:?}", &pledge);

    let cost = reg.cost;
    println!("cost:\t{:?}", &cost);

    let margin = UnitInterval::new(&reg.margin_numerator, &reg.margin_denominator);
    println!("margin:\t{:?}", &margin);

    let mut pool_metadata_bytes = vec![];
    File::open(reg.pool_metadata)?.read_to_end(&mut pool_metadata_bytes)?;
    let pool_metadata_hash = blake2b_256(&pool_metadata_bytes);

    println!("pool_metadata_hash:\t{}", hex::encode(pool_metadata_hash));
    println!("pool_metadata_url:\t{}", reg.pool_metadata_url.url());

    let reward_account_script = Key::from_path(reg.rewards_address)?.plutus_script()?;
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

    // pool owners
    // TODO: support more than 1 owner
    let mut owners = Ed25519KeyHashes::new();
    owners.add(&stake_vkey_operator.hash());

    println!("### relays:");
    println!("{}", serde_yaml::to_string(&reg.relays)?);
    println!("### relays finished");

    let pool_params = PoolParams::new(
        &cold_vkey_operator.hash(),
        &vrf_vkey_hash,
        &pledge,
        &cost,
        &margin,
        &reward_account,
        &owners,
        &reg.relays,
        Some(PoolMetadata::new(
            &reg.pool_metadata_url,
            &PoolMetadataHash::from(pool_metadata_hash),
        )),
    );
    let pool_registration = PoolRegistration::new(&pool_params);
    let pool_registration_certificate = Certificate::new_pool_registration(&pool_registration);

    println!(
        "Pool registration certificate cbor hex: {}",
        hex::encode(pool_registration_certificate.to_bytes())
    );

    // let pool_stake_delegation = StakeDelegation::new(
    //     &StakeCredential::from_keyhash(&stake_vkey_operator.hash()),
    //     &cold_vkey_operator.hash(),
    // );
    // let pool_stake_delegation_certificate =
    //     Certificate::new_stake_delegation(&pool_stake_delegation);

    // println!(
    //     "Pool delegation certificate cbor hex: {}",
    //     hex::encode(pool_stake_delegation_certificate.to_bytes())
    // );

    let mut builder = create_tx_builder();

    let cert_builder = SingleCertificateBuilder::new(&pool_registration_certificate);
    builder.add_cert(&cert_builder.skip_witness());

    // let cert_builder = SingleCertificateBuilder::new(&pool_stake_delegation_certificate);
    // builder.add_cert(&cert_builder.skip_witness());

    let payment_address = get_payment_creds(network, reg.payment_vkey, reg.payment_bech32)?;

    println!(
        "Payment address:\t{}",
        payment_address
            .to_bech32(None)
            .map_err(|err| anyhow!("Can't display payment bech32: {err}"))?
    );

    let fee: u64 = 300000;
    builder.set_fee(&Coin::from(fee));

    // builder.add_required_signer(&stake_vkey_operator.hash());
    // builder.add_required_signer(&cold_vkey_operator.hash());
    // builder.add_required_signer(&payment_address_pk.hash());

    let blockfrost = Blockfrost::new(blockfrost)?;
    fetch_inputs_and_balance_tx(
        &mut builder,
        &reg.inputs,
        &blockfrost,
        &payment_address,
        500000000 + fee,
        0,
    )
    .await?;

    let mut signed_tx_builder = builder
        .build(ChangeSelectionAlgo::Default, &payment_address)
        .map_err(|_err| anyhow!("Can't create tx body"))?;
    let body = signed_tx_builder.body();

    if reg.payment_skey.is_none() || reg.stake_skey.is_none() || reg.cold_skey.is_none() {
        println!("inputs {:?}", body.inputs());
        println!("outputs {:?}", body.outputs());
        println!("fee {:?}", body.fee());

        println!(
            "body: {}",
            hex::encode(Transaction::new(&body, &TransactionWitnessSet::new(), None).to_bytes())
        );
        return Ok(());
    }

    let payment_address_sk = Key::from_path(reg.payment_skey.unwrap())?;
    assert!(matches!(
        payment_address_sk,
        Key::PaymentSigningKeyShelley { .. }
    ));
    let payment_address_sk = payment_address_sk.private_key()?;

    let stake_address_sk = Key::from_path(reg.stake_skey.unwrap())?;
    assert!(matches!(
        stake_address_sk,
        Key::StakeSigningKeyShelley { .. }
    ));
    let stake_address_sk = stake_address_sk.private_key()?;

    let cold_address_sk = Key::from_path(reg.cold_skey.unwrap())?;
    assert!(matches!(cold_address_sk, Key::StakePoolSigningKey { .. }));
    let cold_address_sk = cold_address_sk.private_key()?;

    signed_tx_builder.add_vkey(&make_vkey_witness(
        &hash_transaction(&body),
        &cold_address_sk,
    ));
    signed_tx_builder.add_vkey(&make_vkey_witness(
        &hash_transaction(&body),
        &stake_address_sk,
    ));
    signed_tx_builder.add_vkey(&make_vkey_witness(
        &hash_transaction(&body),
        &payment_address_sk,
    ));

    let tx = signed_tx_builder
        .build_checked()
        .map_err(|err| anyhow!("Can't build tx: {err}"))?;

    println!("inputs {:?}", body.inputs());
    println!("outputs {:?}", body.outputs());
    println!("fee {:?}", body.fee());

    finalize_and_submit_tx(tx, blockfrost, submit).await
}
