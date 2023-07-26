use anyhow::{anyhow, bail, Context};
use cardano_multiplatform_lib::crypto::TransactionHash;
use std::collections::{BTreeMap, HashMap};

use cardano_multiplatform_lib::builders::redeemer_builder::RedeemerWitnessKey;

use crate::utils::parse_asset;
use cardano_multiplatform_lib::ledger::common::value::{to_bignum, BigNum, Value};
use cardano_multiplatform_lib::plutus::{ExUnits, Redeemer, RedeemerTag, Redeemers};
use cardano_multiplatform_lib::{Assets, MultiAsset, Transaction};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{header, Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct BlockfrostConfiguration {
    pub endpoint: String,
    pub key: String,
}

#[derive(Deserialize, Debug)]
struct TxUtxos {
    outputs: Vec<TxOutput>,
}

#[derive(Deserialize, Debug)]
struct TxOutput {
    amount: Vec<AssetAmount>,
}

#[derive(Deserialize, Debug)]
pub struct AssetAmount {
    pub unit: String,
    pub quantity: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RedeemerResult {
    pub result: Option<EvaluationResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluationResult {
    #[serde(rename = "EvaluationResult")]
    pub evaluation_result: Option<HashMap<String, ExUnitResult>>,
    #[serde(rename = "EvaluationFailure")]
    pub evaluation_failure: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExUnitResult {
    pub memory: u64,
    pub steps: u64,
}

pub struct Blockfrost {
    config: BlockfrostConfiguration,
    client: Client,
}

impl BlockfrostConfiguration {
    pub fn get_network(&self) -> u8 {
        if self.endpoint.contains("preprod") || self.endpoint.contains("preview") {
            0
        } else {
            1
        }
    }
}

impl Blockfrost {
    pub fn new(config: BlockfrostConfiguration) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/cbor"),
        );
        headers.append(
            "project_id",
            HeaderValue::from_str(&config.key).map_err(|err| {
                anyhow!("The project_id (authentication key) is not in a valid format {err:?}")
            })?,
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|err| anyhow!("Failed to build HTTP Client {err:?}"))?;

        Ok(Self { config, client })
    }

    pub async fn get_utxo_info(
        &self,
        tx_id: String,
        index: u64,
    ) -> anyhow::Result<Vec<AssetAmount>> {
        let req = self
            .client
            .get(self.url(format!("api/v0/txs/{tx_id}/utxos")))
            .send()
            .await
            .context("Failed to get utxos for transaction")?;

        match req.status() {
            StatusCode::OK => {
                let mut payload = req
                    .json::<TxUtxos>()
                    .await
                    .context("Request response is not json")?;

                Ok(payload.outputs.swap_remove(index as usize).amount)
            }
            StatusCode::NOT_FOUND => bail!("transaction not found"),
            _ => {
                let error: BlockFrostError =
                    req.json().await.context("expected error to be decoded")?;

                bail!(
                    "{error}: {message}",
                    error = error.error,
                    message = error.message
                )
            }
        }
    }

    #[allow(unused)]
    pub async fn get_exec_units(&self, transaction: &Transaction) -> anyhow::Result<Redeemers> {
        let bytes = transaction.to_bytes();
        let req = self
            .client
            .post(self.url("api/v0/utils/txs/evaluate"))
            .body(bytes)
            .send()
            .await
            .map_err(|err| {
                anyhow!(
                    "Failed to submit transaction for evaluation to blockfrost endpoint: {err:?}"
                )
            })?;

        if req.status() == StatusCode::OK {
            let redeemer_result = req
                .json::<RedeemerResult>()
                .await
                .context("Request response is not json")?;
            match redeemer_result.result {
                Some(res) => {
                    if let Some(e) = &res.evaluation_failure {
                        return Err(anyhow!(serde_json::to_string_pretty(&e).unwrap(),));
                    }
                    let mut redeemers: BTreeMap<RedeemerWitnessKey, Redeemer> = BTreeMap::new();
                    for (pointer, eu) in &res.evaluation_result.unwrap() {
                        let r: Vec<&str> = pointer.split(':').collect();
                        let tag = match r[0] {
                            "spend" => RedeemerTag::new_spend(),
                            "mint" => RedeemerTag::new_mint(),
                            "certificate" => RedeemerTag::new_cert(),
                            "withdrawal" => RedeemerTag::new_reward(),
                            _ => return Err(anyhow!("Null tag")),
                        };
                        let index = &to_bignum(r[1].parse::<u64>().unwrap());
                        let ex_units = ExUnits::new(&to_bignum(eu.memory), &to_bignum(eu.steps));
                        for redeemer_index in 0..transaction
                            .witness_set()
                            .redeemers()
                            .map(|redeemers| redeemers.len())
                            .unwrap_or(0)
                        {
                            let tx_redeemer = transaction
                                .witness_set()
                                .redeemers()
                                .ok_or(anyhow!("Can't get redeemer"))?
                                .get(redeemer_index);

                            if tx_redeemer.tag() == tag && tx_redeemer.index() == *index {
                                let updated_redeemer = Redeemer::new(
                                    &tx_redeemer.tag(),
                                    &tx_redeemer.index(),
                                    &tx_redeemer.data(),
                                    &ex_units,
                                );
                                redeemers.insert(
                                    RedeemerWitnessKey::new(
                                        &updated_redeemer.tag(),
                                        &updated_redeemer.index(),
                                    ),
                                    updated_redeemer.clone(),
                                );
                            }
                        }
                    }

                    let mut redeemers_result = Redeemers::new();
                    redeemers
                        .values()
                        .map(|redeemer| {
                            redeemers_result.add(redeemer);
                        })
                        .collect::<()>();
                    Ok(redeemers_result)
                }

                None => Err(anyhow!("No redeemer result")),
            }
        } else {
            let error: BlockFrostError = req
                .json()
                .await
                .map_err(|err| anyhow!("expected error to be decoded, {err:?}"))?;

            Err(anyhow!("{}: {}", error.error, error.message))
        }
    }

    fn url(&self, api: impl fmt::Display) -> String {
        format!(
            "{endpoint}/{api}",
            endpoint = self.config.endpoint,
            api = api
        )
    }

    pub async fn v0_tx_submit(
        &self,
        transaction: &Transaction,
    ) -> anyhow::Result<anyhow::Result<TransactionHash>> {
        let bytes = transaction.to_bytes();
        let req = self
            .client
            .post(self.url("api/v0/tx/submit"))
            .body(bytes)
            .send()
            .await
            .map_err(|err| {
                anyhow!("Failed to submit transaction to blockfrost endpoint: {err:?}")
            })?;

        if req.status() == StatusCode::OK {
            let bf_id: String = req.json().await.map_err(|err|
                anyhow!("Expect the end point to return confirmation about the transaction being submitted {err:?}")
            )?;

            TransactionHash::from_bytes(
                hex::decode(bf_id)
                    .map_err(|err| anyhow!("Blockfrost should return an ID: {err:?}"))?,
            )
            .map_err(|error| anyhow!("Failed to decode expected transaction id: {error}"))
            .map(Ok)
        } else {
            let error: BlockFrostError = req
                .json()
                .await
                .map_err(|err| anyhow!("expected error to be decoded, {err:?}"))?;

            Ok(Err(anyhow!("{}: {}", error.error, error.message)))
        }
    }
}

#[derive(Deserialize)]
struct BlockFrostError {
    error: String,
    message: String,
}

impl From<AssetAmount> for Value {
    fn from(value: AssetAmount) -> Self {
        if value.unit == "lovelace" {
            Value::new(&BigNum::from_str(&value.quantity).unwrap())
        } else {
            let mut ma = MultiAsset::new();

            let (policy_id, asset_name) = parse_asset(&value.unit).unwrap();

            let mut assets = Assets::new();
            assets.insert(&asset_name, &BigNum::from_str(&value.quantity).unwrap());
            ma.insert(&policy_id, &assets);

            Value::new_from_assets(&ma)
        }
    }
}
