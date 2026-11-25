mod archive;
pub mod builder;
mod cli;
mod crypto;
mod proxmox;
pub mod release_v2;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use cli::{Cli, Command};
use crypto::{Decision, Role};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { role, out } => {
            crypto::keygen(role, &out)?;
        }
        Command::Pack {
            path,
            script,
            key,
            output,
        } => {
            archive::pack(&path, &script, &key, &output)?;
            println!("Packed and signed by Developer: {}", output.display());
        }
        Command::Ls { archive: path } => {
            let package = archive::Package::read(&path)?;
            println!("Entries: payload.tar.zst, build.script, manifest.json");
            println!("Payload BLAKE3: {}", package.manifest.payload_hash);
            println!("Script BLAKE3: {}", package.manifest.script_hash);
            let trust = crypto::trust_dir()?;
            package.verify(&trust)?;
            for attestation in &package.manifest.attestations {
                println!(
                    "{:?}: valid and trusted ({:?})",
                    attestation.role, attestation.decision
                );
                if let Some(reason) = &attestation.reason {
                    println!("  Reason: {reason}");
                }
                for (target, hash) in &attestation.outputs {
                    println!("  {target}: {hash}");
                }
            }
            println!(
                "Chain: valid; {} of 5 stages",
                package.manifest.attestations.len()
            );
        }
        Command::Unpack {
            archive: path,
            dest,
        } => {
            let package = archive::Package::read(&path)?;
            package.verify(&crypto::trust_dir()?)?;
            package.ensure_not_rejected()?;
            package.unpack(&dest)?;
            println!("Verified payload extracted to {}", dest.display());
        }
        Command::Submit { archive: path } => {
            let package = archive::Package::read(&path)?;
            package.verify(&crypto::trust_dir()?)?;
            package.ensure_stage(Role::Developer)?;
            println!("Submission for review prepared locally; no network request was made.");
        }
        Command::Audit { archive: path, key } => {
            let mut package = archive::Package::read(&path)?;
            let trust = crypto::trust_dir()?;
            package.verify(&trust)?;
            package.ensure_stage(Role::Developer)?;
            package.validate_for_review()?;
            package.attest(Role::Reviewer, Decision::Approve, None, &key, &trust)?;
            package.write_replace(&path)?;
            println!("Reviewer approved after structural validation; the script was not executed.");
        }
        Command::Reject {
            archive: path,
            reason,
            key,
        } => {
            ensure!(
                !reason.trim().is_empty(),
                "rejection reason must not be empty"
            );
            let mut package = archive::Package::read(&path)?;
            let trust = crypto::trust_dir()?;
            package.verify(&trust)?;
            package.ensure_stage(Role::Developer)?;
            package.attest(Role::Reviewer, Decision::Reject, Some(reason), &key, &trust)?;
            package.write_replace(&path)?;
            println!(
                "Reviewer rejected the package; the developer must create and submit a corrected package."
            );
        }
        Command::Approve {
            archive: path,
            key,
            cpu,
            thread,
            memory,
        } => {
            let resources = proxmox::Resources::new(cpu, thread, memory)?;
            let mut package = archive::Package::read(&path)?;
            let trust = crypto::trust_dir()?;
            package.verify(&trust)?;
            package.ensure_stage(Role::Reviewer)?;
            package.attest(Role::Manager, Decision::Approve, None, &key, &trust)?;
            package.write_replace(&path)?;
            proxmox::submit(&resources)
                .await
                .context("Proxmox orchestration")?;
        }
        Command::Ssh { temp_name } => {
            proxmox::ssh(&temp_name).await?;
        }
    }
    Ok(())
}
