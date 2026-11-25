use crate::crypto::Role;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "anynix", version, about = "Build package attestation tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Keygen {
        #[arg(long, value_enum)]
        role: Role,
        #[arg(long)]
        out: PathBuf,
    },
    Pack {
        path: PathBuf,
        #[arg(long)]
        script: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(short = 'o', long)]
        output: PathBuf,
    },
    Ls {
        archive: PathBuf,
    },
    Unpack {
        archive: PathBuf,
        #[arg(short = 'o', long)]
        dest: PathBuf,
    },
    Submit {
        archive: PathBuf,
    },
    Audit {
        archive: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    Reject {
        archive: PathBuf,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        key: PathBuf,
    },
    Approve {
        archive: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value_t = 1)]
        cpu: u8,
        #[arg(long, default_value_t = 1)]
        thread: u8,
        #[arg(long, default_value = "1G")]
        memory: String,
    },
    Ssh {
        temp_name: String,
    },
}
