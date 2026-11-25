use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use ed25519_dalek::{
    Signature, Signer, SigningKey, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
pub enum Role {
    Developer,
    Reviewer,
    Manager,
    BuildServer,
    ReleaseAuthority,
}

impl Role {
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Developer => "developer.pem",
            Self::Reviewer => "reviewer.pem",
            Self::Manager => "manager.pem",
            Self::BuildServer => "build-server.pem",
            Self::ReleaseAuthority => "release-authority.pem",
        }
    }
}

const ROLES: [Role; 5] = [
    Role::Developer,
    Role::Reviewer,
    Role::Manager,
    Role::BuildServer,
    Role::ReleaseAuthority,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Decision {
    Approve,
    Reject,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub role: Role,
    pub decision: Decision,
    pub reason: Option<String>,
    pub outputs: BTreeMap<String, String>,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u8,
    pub payload_hash: String,
    pub script_hash: String,
    pub attestations: Vec<Attestation>,
}

#[derive(Serialize)]
struct SignedMessage<'a> {
    domain: &'static str,
    payload_hash: &'a str,
    script_hash: &'a str,
    previous: Option<String>,
    role: Role,
    decision: Decision,
    reason: &'a Option<String>,
    outputs: &'a BTreeMap<String, String>,
    public_key: &'a str,
}

pub fn hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

pub(crate) fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    ensure!(
        value.len() == N * 2
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid canonical hex encoding"
    );
    let mut result = [0; N];
    for (i, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        result[i] = digit(chunk[0]) * 16 + digit(chunk[1]);
    }
    Ok(result)
}

pub fn trust_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("ANYNIX_TRUST_DIR") {
        ensure!(!path.is_empty(), "ANYNIX_TRUST_DIR must not be empty");
        return Ok(path.into());
    }
    let home = std::env::var_os("HOME").context("HOME or ANYNIX_TRUST_DIR is required")?;
    Ok(PathBuf::from(home).join(".config/anynix/trust"))
}

fn trusted_key(role: Role, trust: &Path) -> Result<VerifyingKey> {
    let path = trust.join(role.file_name());
    let pem = fs::read_to_string(&path)
        .with_context(|| format!("reading trusted {:?} key {}", role, path.display()))?;
    VerifyingKey::from_public_key_pem(&pem).context("invalid trusted public key")
}

pub fn load_key(path: &Path) -> Result<SigningKey> {
    let pem = fs::read_to_string(path)
        .with_context(|| format!("reading private key {}", path.display()))?;
    SigningKey::from_pkcs8_pem(&pem).context("invalid Ed25519 private key")
}

pub fn keygen(role: Role, out: &Path) -> Result<()> {
    use std::io::Write;
    let key = SigningKey::generate(&mut OsRng);
    let private = key
        .to_pkcs8_pem(Default::default())
        .context("encoding private key")?;
    let public = key
        .verifying_key()
        .to_public_key_pem(Default::default())
        .context("encoding public key")?;
    let mut public_name = out.as_os_str().to_os_string();
    public_name.push(".pub.pem");
    let public_path = PathBuf::from(public_name);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut private_file = opts
        .open(out)
        .with_context(|| format!("creating {}", out.display()))?;
    let result = (|| -> Result<()> {
        private_file.write_all(private.as_bytes())?;
        private_file.sync_all()?;
        let mut public_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&public_path)
            .with_context(|| format!("creating {}", public_path.display()))?;
        if let Err(error) = public_file
            .write_all(public.as_bytes())
            .and_then(|_| public_file.sync_all())
        {
            fs::remove_file(&public_path).context("cleaning up incomplete public key")?;
            return Err(error.into());
        }
        Ok(())
    })();
    if result.is_err() {
        fs::remove_file(out).context("cleaning up incomplete private key")?;
    }
    result?;
    println!(
        "Generated {:?} key: {}; public key: {}",
        role,
        out.display(),
        public_path.display()
    );
    println!(
        "Install the public key as {} in your trusted key directory.",
        role.file_name()
    );
    Ok(())
}

fn message(manifest: &Manifest, index: usize, entry: &Attestation) -> Result<[u8; 32]> {
    let previous = if index == 0 {
        None
    } else {
        Some(hash(&serde_json::to_vec(
            &manifest.attestations[index - 1],
        )?))
    };
    let value = SignedMessage {
        domain: "anynix-attestation-v1",
        payload_hash: &manifest.payload_hash,
        script_hash: &manifest.script_hash,
        previous,
        role: entry.role,
        decision: entry.decision,
        reason: &entry.reason,
        outputs: &entry.outputs,
        public_key: &entry.public_key,
    };
    Ok(*blake3::hash(&serde_json::to_vec(&value)?).as_bytes())
}

impl Manifest {
    pub fn new(payload: &[u8], script: &[u8]) -> Self {
        Self {
            version: 1,
            payload_hash: hash(payload),
            script_hash: hash(script),
            attestations: Vec::new(),
        }
    }

    pub fn sign(
        &mut self,
        role: Role,
        decision: Decision,
        reason: Option<String>,
        outputs: BTreeMap<String, String>,
        key: &SigningKey,
    ) -> Result<()> {
        ensure!(
            ROLES.get(self.attestations.len()) == Some(&role),
            "invalid attestation order"
        );
        let mut entry = Attestation {
            role,
            decision,
            reason,
            outputs,
            public_key: hex(key.verifying_key().as_bytes()),
            signature: String::new(),
        };
        validate_entry(&entry)?;
        entry.signature = hex(&key
            .sign(&message(self, self.attestations.len(), &entry)?)
            .to_bytes());
        self.attestations.push(entry);
        Ok(())
    }

    pub fn verify(&self, payload: &[u8], script: &[u8], trust: &Path) -> Result<()> {
        ensure!(self.version == 1, "unsupported manifest version");
        ensure!(self.payload_hash == hash(payload), "payload hash mismatch");
        ensure!(self.script_hash == hash(script), "script hash mismatch");
        ensure!(
            !self.attestations.is_empty() && self.attestations.len() <= ROLES.len(),
            "invalid chain length"
        );
        for (index, entry) in self.attestations.iter().enumerate() {
            ensure!(entry.role == ROLES[index], "invalid attestation order");
            validate_entry(entry)?;
            if index > 0 {
                ensure!(
                    self.attestations[index - 1].decision != Decision::Reject,
                    "attestation follows a rejection"
                );
            }
            let key = VerifyingKey::from_bytes(&decode_hex::<32>(&entry.public_key)?)
                .context("invalid public key")?;
            ensure!(
                trusted_key(entry.role, trust)? == key,
                "untrusted {:?} key",
                entry.role
            );
            let signature = Signature::from_bytes(&decode_hex::<64>(&entry.signature)?);
            key.verify_strict(&message(self, index, entry)?, &signature)
                .with_context(|| format!("invalid {:?} signature", entry.role))?;
        }
        Ok(())
    }
}

fn validate_entry(entry: &Attestation) -> Result<()> {
    match (entry.role, entry.decision, &entry.reason) {
        (Role::Reviewer, Decision::Reject, Some(reason)) if !reason.trim().is_empty() => {}
        (_, Decision::Approve, None) => {}
        _ => bail!("invalid decision or rejection reason"),
    }
    if entry.role == Role::BuildServer {
        ensure!(
            entry.outputs.len() == 3,
            "BuildServer must attest Linux, FreeBSD and Haiku outputs"
        );
        for name in ["Linux", "FreeBSD", "Haiku"] {
            decode_hex::<32>(
                entry
                    .outputs
                    .get(name)
                    .context("missing target output hash")?,
            )?;
        }
    } else {
        ensure!(
            entry.outputs.is_empty(),
            "output hashes only belong to BuildServer"
        );
    }
    Ok(())
}

pub fn ensure_trusted_signer(role: Role, key: &SigningKey, trust: &Path) -> Result<()> {
    ensure!(
        trusted_key(role, trust)? == key.verifying_key(),
        "private key is not trusted for {:?}",
        role
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Manifest) {
        let trust = tempfile::tempdir().unwrap();
        let mut manifest = Manifest::new(b"payload", b"script");
        for role in [Role::Developer, Role::Reviewer, Role::Manager] {
            let key = SigningKey::generate(&mut OsRng);
            fs::write(
                trust.path().join(role.file_name()),
                key.verifying_key()
                    .to_public_key_pem(Default::default())
                    .unwrap(),
            )
            .unwrap();
            manifest
                .sign(role, Decision::Approve, None, BTreeMap::new(), &key)
                .unwrap();
        }
        (trust, manifest)
    }

    #[test]
    fn payload_single_byte_change_invalidates_chain() {
        let (trust, manifest) = setup();
        assert!(manifest.verify(b"payload", b"script", trust.path()).is_ok());
        assert!(
            manifest
                .verify(b"Payload", b"script", trust.path())
                .is_err()
        );
    }

    #[test]
    fn intermediate_signature_byte_change_invalidates_chain() {
        let (trust, mut manifest) = setup();
        assert!(manifest.verify(b"payload", b"script", trust.path()).is_ok());
        let signature = &mut manifest.attestations[1].signature;
        signature.replace_range(0..2, if &signature[0..2] == "00" { "01" } else { "00" });
        assert!(
            manifest
                .verify(b"payload", b"script", trust.path())
                .is_err()
        );
    }
}
