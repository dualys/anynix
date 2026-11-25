use anyhow::{Result, ensure};
use thiserror::Error;

#[derive(Debug)]
pub struct Resources {
    cpu: u8,
    threads: u8,
    memory: String,
}

impl Resources {
    pub fn new(cpu: u8, threads: u8, memory: String) -> Result<Self> {
        ensure!(cpu > 0 && threads > 0, "cpu and thread must be nonzero");
        let digits = memory.trim_end_matches(['K', 'M', 'G', 'T']);
        ensure!(
            digits.len() + 1 == memory.len() && digits.parse::<u64>().is_ok_and(|n| n > 0),
            "memory must be a positive integer followed by K, M, G or T"
        );
        Ok(Self {
            cpu,
            threads,
            memory,
        })
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
struct NotImplemented(&'static str);

pub async fn submit(resources: &Resources) -> Result<()> {
    let _client = reqwest::Client::new();
    println!(
        "Proxmox simulation: cpu={}, threads={}, memory={}.",
        resources.cpu, resources.threads, resources.memory
    );
    // TODO: authenticate to Proxmox, schedule isolated builds, and verify returned artifacts.
    // TODO: obtain a BuildServer attestation and an independent ReleaseAuthority signature.
    Err(NotImplemented(
        "no build was started; BuildServer and ReleaseAuthority attestations are missing",
    )
    .into())
}

pub async fn ssh(_temp_name: &str) -> Result<()> {
    // TODO: resolve an authorized running VM and invoke SSH with verified host keys.
    Err(NotImplemented("SSH is unavailable: Proxmox integration is not implemented").into())
}
