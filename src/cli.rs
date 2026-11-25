use crate::crypto::Role;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "anynix",
    version,
    about = "Create and verify signed Unix package archives"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate an Ed25519 key pair for a signing role
    Keygen {
        /// Role associated with this key pair
        #[arg(long, value_enum)]
        role: Role,
        /// Private key path; the public key is written to <path>.pub.pem
        #[arg(long)]
        out: PathBuf,
    },
    /// Package files selected by anynix.yaml and sign them as Developer
    Pack {
        /// Source directory to freeze into the archive
        path: PathBuf,
        /// UTF-8 build script to include
        #[arg(long)]
        script: PathBuf,
        /// Developer's Ed25519 private key
        #[arg(long)]
        key: PathBuf,
        /// Destination .anynix archive; must not already exist
        #[arg(short = 'o', long)]
        output: PathBuf,
    },
    /// Show archive hashes and verify the attestation chain against trusted keys
    Ls {
        /// Archive to inspect
        archive: PathBuf,
    },
    /// Verify the archive and extract its source payload into a new directory
    Unpack {
        /// Archive to verify and extract
        archive: PathBuf,
        /// New destination directory
        #[arg(short = 'o', long)]
        dest: PathBuf,
    },
    /// Verify and prepare a submission locally; network transfer is not implemented
    Submit {
        /// Developer-signed archive
        archive: PathBuf,
    },
    /// Validate the payload structure and add a Reviewer signature
    Audit {
        /// Developer-signed archive to review
        archive: PathBuf,
        /// Reviewer's trusted Ed25519 private key
        #[arg(long)]
        key: PathBuf,
    },
    /// Sign a Reviewer rejection and its reason
    Reject {
        /// Developer-signed archive to reject
        archive: PathBuf,
        /// Explanation to send back to the developer
        #[arg(long)]
        reason: String,
        /// Reviewer's trusted Ed25519 private key
        #[arg(long)]
        key: PathBuf,
    },
    /// Sign as Manager; Proxmox build orchestration is not implemented
    Approve {
        /// Archive approved by a Reviewer
        archive: PathBuf,
        /// Manager's trusted Ed25519 private key
        #[arg(long)]
        key: PathBuf,
        /// Requested number of CPUs
        #[arg(long, default_value_t = 1)]
        cpu: u8,
        /// Requested number of threads
        #[arg(long, default_value_t = 1)]
        thread: u8,
        /// Requested memory, e.g. 4G
        #[arg(long, default_value = "1G")]
        memory: String,
    },
    /// Connect to a build VM (not implemented)
    Ssh {
        /// Name of the ephemeral build VM
        temp_name: String,
    },
}
