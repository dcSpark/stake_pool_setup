mod blockfrost;
mod cip1852;
mod handlers;
mod keys;
mod utils;
mod utxo_pointer;

use crate::blockfrost::BlockfrostConfiguration;
use crate::handlers::create_nft::{handle_create_nft, CreateNFT};
use crate::handlers::delegate_rewards::{handle_delegate_rewards, DelegateRewards};
use crate::handlers::regcert::{handle_issue_reg_cert, IssueRegistrationCeritifcate};
use crate::handlers::register_rewards_address::{handle_register_rewards, RegisterRewards};
use crate::handlers::send_tx::{handle_send_tx, SendTransaction};
use crate::handlers::withdraw_rewards::{handle_withdraw_rewards, WithdrawRewards};

use anyhow::Context;

use clap::Parser;

use std::fs::File;

use std::path::PathBuf;

#[derive(Parser)]
pub struct CommandLine {
    #[clap(subcommand)]
    command: Command,
    #[clap(long, value_parser)]
    blockfrost: PathBuf,
    #[arg(long)]
    submit: bool,
}

#[derive(Parser)]
pub enum Command {
    Empty,
    IssueRegCertificate(IssueRegistrationCeritifcate),
    DelegateRewards(DelegateRewards),
    RegisterRewards(RegisterRewards),
    WithdrawRewards(WithdrawRewards),
    CreateNFT(CreateNFT),
    SendTransaction(SendTransaction),
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let CommandLine {
        command,
        blockfrost,
        submit,
    } = CommandLine::parse();

    let config: BlockfrostConfiguration = serde_yaml::from_reader(
        File::open(blockfrost).context("failed to open the blockfrost config file")?,
    )?;

    match command {
        Command::IssueRegCertificate(reg) => handle_issue_reg_cert(reg, config, submit).await,
        Command::Empty => {
            println!("Params:\nblockfrost: {:?}\nsubmit: {}", config, submit);
            Ok(())
        }
        Command::CreateNFT(create_nft) => handle_create_nft(create_nft, config, submit).await,
        Command::DelegateRewards(delegate) => {
            handle_delegate_rewards(delegate, config, submit).await
        }
        Command::RegisterRewards(register) => {
            handle_register_rewards(register, config, submit).await
        }
        Command::WithdrawRewards(withdraw_rewards) => {
            handle_withdraw_rewards(withdraw_rewards, config, submit).await
        }
        Command::SendTransaction(send_tx) => handle_send_tx(send_tx, config).await,
    }
}
