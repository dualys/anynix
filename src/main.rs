mod archive;
pub mod builder;
mod cli;
mod crypto;
mod git_update;
mod install;
mod proxmox;
pub mod release_v2;
mod review_client;
mod review_server;
mod runner;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use cli::{Cli, Command, ReviewCommand};
use crypto::{Decision, Role};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    execute(Cli::parse().command).await
}

pub(crate) async fn execute(command: Command) -> Result<()> {
    match command {
        Command::Keygen { role, out } => {
            crypto::keygen(role, &out)?;
        }
        Command::Pack {
            path,
            script,
            key,
            output,
        } => {
            let key = match key {
                Some(key) => key,
                None => crypto::developer_key_path()?,
            };
            let output = output.unwrap_or_else(|| "package.anynix".into());
            archive::pack(&path, script.as_deref(), &key, &output)?;
            println!("Packed and signed by Developer: {}", output.display());
        }
        Command::Update {
            archive,
            repository,
            branch,
            key,
            output,
        } => {
            let key = match key {
                Some(key) => key,
                None => crypto::developer_key_path()?,
            };
            let commit = git_update::update(
                &archive,
                repository.as_deref(),
                branch.as_deref(),
                &key,
                &output,
            )?;
            println!(
                "Updated from commit {commit}, signed by Developer: {}",
                output.display()
            );
        }
        Command::Diff { archive, path } => {
            let package = archive::Package::read(&archive)?;
            package.verify(&crypto::trust_dir()?)?;
            let temporary = tempfile::tempdir()?;
            let archived = temporary.path().join("archive");
            let local = temporary.path().join("local");
            package.unpack(&archived)?;
            archive::snapshot_for_diff(&path, &local)?;
            let status = std::process::Command::new("git")
                .args([
                    "--no-pager",
                    "diff",
                    "--no-index",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--",
                ])
                .arg(&archived)
                .arg(&local)
                .status()
                .context("running git diff")?;
            match status.code() {
                Some(0) => println!("No differences in selected sources."),
                Some(1) => {}
                _ => anyhow::bail!("git diff failed: {status}"),
            }
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
        Command::Run {
            prefix,
            program,
            args,
        } => runner::run(&prefix, &program, &args)?,
        Command::Install {
            package,
            repository,
            trust_root,
            state,
            prefix,
        } => {
            install::install(&package, &repository, &trust_root, &state, &prefix).await?;
            println!("Installed {package} into {}", prefix.display());
        }
        Command::Submit {
            archive: path,
            server,
            correction_of,
        } => {
            let package = archive::Package::read(&path)?;
            package.verify(&crypto::trust_dir()?)?;
            package.ensure_stage(Role::Developer)?;
            if let Some(server) = server {
                review_client::submit(&server, &path, correction_of).await?;
            } else {
                ensure!(correction_of.is_none(), "--correction-of requires --server");
                println!("Submission for review prepared locally; no network request was made.");
            }
        }
        Command::Review { command } => match command {
            ReviewCommand::Serve {
                config,
                database,
                listen,
            } => {
                review_server::serve(&config, &database, listen).await?;
            }
            ReviewCommand::TokenHash => {
                println!("{}", crypto::hash(review_client::token()?.as_bytes()));
            }
            ReviewCommand::List { server } => {
                review_client::list(&server).await?;
            }
            ReviewCommand::Get {
                id,
                server,
                original,
                reviewer,
                output,
            } => {
                review_client::get(&server, id, original, reviewer, &output).await?;
            }
            ReviewCommand::Send {
                id,
                archive: path,
                server,
            } => {
                let package = archive::Package::read(&path)?;
                package.verify(&crypto::trust_dir()?)?;
                let manager = match package.manifest.attestations.as_slice() {
                    [_, reviewer] if reviewer.role == Role::Reviewer => false,
                    [_, _, manager] if manager.role == Role::Manager => true,
                    _ => anyhow::bail!("expected a Reviewer or Manager decision"),
                };
                review_client::send(&server, id, &path, manager).await?;
            }
        },
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
            review_only,
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
            if review_only {
                println!("Manager approved; no build was started.");
                return Ok(());
            }
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
