//! Cryptographic primitives for v2 releases. This module does not implement TUF
//! and must not be used alone as an authorization or freshness check.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto::decode_hex;

const MAX_INTEGER: u64 = (1 << 53) - 1;
const ROLES: [&str; 5] = [
    "Developer",
    "Reviewer",
    "Manager",
    "BuildServer",
    "ReleaseAuthority",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceContent {
    pub payload: Blob,
    pub build_script: Blob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub format: String,
    pub package: String,
    pub version: String,
    pub source: SourceContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDownload {
    pub url: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub package: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub digest: String,
    pub size: u64,
    pub install_path: String,
    pub permissions: u64,
    #[serde(rename = "type")]
    pub file_type: FileType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    Binary,
    Configuration,
    Documentation,
    Manual,
    Source,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase", deny_unknown_fields)]
pub enum Target {
    Success {
        os: String,
        architecture: String,
        dependencies: Vec<Dependency>,
        files: Vec<File>,
    },
    Failed {
        os: String,
        architecture: String,
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub format: String,
    pub package: String,
    pub version: String,
    #[serde(deserialize_with = "required_option")]
    pub license: Option<String>,
    pub source: SourceContent,
    pub sources: Vec<SourceDownload>,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub role: String,
    pub decision: String,
    pub subject: String,
    #[serde(deserialize_with = "required_option")]
    pub previous: Option<String>,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub source: Source,
    pub release: Release,
    pub attestations: Vec<Attestation>,
}

impl Blob {
    pub fn verify_content(&self, bytes: &[u8]) -> Result<()> {
        blob(&self.digest, self.size)?;
        ensure!(self.size == bytes.len() as u64, "blob size mismatch");
        ensure!(
            self.digest == blake3::hash(bytes).to_hex().as_str(),
            "blob hash mismatch"
        );
        Ok(())
    }
}

#[derive(Serialize)]
struct Message<'a> {
    domain: &'static str,
    role: &'a str,
    decision: &'a str,
    subject: &'a str,
    previous: &'a Option<String>,
    public_key: &'a str,
}

fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(blake3::hash(&serde_json_canonicalizer::to_vec(value)?)
        .to_hex()
        .to_string())
}

fn required_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

fn blob(digest: &str, size: u64) -> Result<()> {
    decode_hex::<32>(digest).context("invalid BLAKE3 digest")?;
    ensure!(size <= MAX_INTEGER, "size exceeds JSON safe integer range");
    Ok(())
}

fn package(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._+-".contains(&b))
}

fn version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "latest"
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+~-".contains(&b))
}

fn target_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

fn install_path(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(['\\', '\0'])
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

impl Source {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "anynix-source-v2",
            "unsupported source format"
        );
        ensure!(package(&self.package), "invalid package name");
        ensure!(version(&self.version), "invalid version");
        blob(&self.source.payload.digest, self.source.payload.size)?;
        blob(
            &self.source.build_script.digest,
            self.source.build_script.size,
        )?;
        Ok(())
    }

    pub fn verify_content(&self, payload: &[u8], script: &[u8]) -> Result<()> {
        self.validate()?;
        for (reference, bytes) in [
            (&self.source.payload, payload),
            (&self.source.build_script, script),
        ] {
            reference.verify_content(bytes)?;
        }
        Ok(())
    }
}

impl Release {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "anynix-release-v2",
            "unsupported release format"
        );
        ensure!(
            package(&self.package) && version(&self.version),
            "invalid package or version"
        );
        ensure!(
            self.license.as_ref().is_none_or(|value| !value.is_empty()),
            "empty license"
        );
        blob(&self.source.payload.digest, self.source.payload.size)?;
        blob(
            &self.source.build_script.digest,
            self.source.build_script.size,
        )?;
        for source in &self.sources {
            ensure!(!source.url.is_empty(), "empty source URL");
            blob(&source.digest, source.size)?;
        }
        let mut targets = BTreeSet::new();
        for target in &self.targets {
            let (os, architecture) = match target {
                Target::Success {
                    os,
                    architecture,
                    dependencies,
                    files,
                } => {
                    ensure!(!files.is_empty(), "successful target has no files");
                    let mut names = BTreeSet::new();
                    for dependency in dependencies {
                        ensure!(
                            package(&dependency.package) && version(&dependency.version),
                            "invalid dependency"
                        );
                        ensure!(names.insert(&dependency.package), "duplicate dependency");
                    }
                    let mut paths = BTreeSet::new();
                    for file in files {
                        blob(&file.digest, file.size)?;
                        ensure!(
                            install_path(&file.install_path),
                            "invalid installation path"
                        );
                        ensure!(file.permissions <= 0o777, "invalid file permissions");
                        ensure!(
                            paths.insert(&file.install_path),
                            "duplicate installation path"
                        );
                    }
                    (os, architecture)
                }
                Target::Failed {
                    os,
                    architecture,
                    error,
                } => {
                    ensure!(!error.is_empty(), "empty build error");
                    (os, architecture)
                }
            };
            ensure!(
                target_id(os) && target_id(architecture),
                "invalid target identifier"
            );
            ensure!(targets.insert((os, architecture)), "duplicate target");
        }
        Ok(())
    }

    pub fn verify_required_targets(&self, required: &BTreeSet<(String, String)>) -> Result<()> {
        self.validate()?;
        ensure!(!required.is_empty(), "required target policy is empty");
        let successful: BTreeSet<_> = self
            .targets
            .iter()
            .filter_map(|target| match target {
                Target::Success {
                    os, architecture, ..
                } => Some((os.clone(), architecture.clone())),
                Target::Failed { .. } => None,
            })
            .collect();
        for target in required {
            ensure!(
                successful.contains(target),
                "required target {}/{} did not succeed",
                target.0,
                target.1
            );
        }
        Ok(())
    }
}

impl Envelope {
    /// Validates schema and signatures against caller-supplied role keys.
    ///
    /// This does not authenticate the key policy, check TUF freshness or
    /// rollback, verify build outputs, or authorize publication/installation.
    pub fn verify_signatures(&self, role_keys: &BTreeMap<String, BTreeSet<String>>) -> Result<()> {
        ensure!(role_keys.len() == ROLES.len(), "invalid role key policy");
        let mut all_keys = BTreeSet::new();
        for role in ROLES {
            let keys = role_keys.get(role).context("missing role key policy")?;
            ensure!(!keys.is_empty(), "empty role key policy for {role}");
            for key in keys {
                VerifyingKey::from_bytes(&decode_hex::<32>(key)?).context("invalid policy key")?;
                ensure!(all_keys.insert(key), "key appears in more than one role");
            }
        }
        self.source.validate()?;
        self.release.validate()?;
        ensure!(
            self.source.package == self.release.package
                && self.source.version == self.release.version
                && self.source.source == self.release.source,
            "source and release do not match"
        );
        ensure!(
            self.attestations.len() == ROLES.len(),
            "expected five attestations"
        );
        let source_hash = digest(&self.source)?;
        let release_hash = digest(&self.release)?;
        for (index, entry) in self.attestations.iter().enumerate() {
            ensure!(entry.role == ROLES[index], "incorrect attestation order");
            ensure!(entry.decision == "Approve", "release contains non-approval");
            ensure!(
                entry.subject.as_str()
                    == if index < 3 {
                        source_hash.as_str()
                    } else {
                        release_hash.as_str()
                    },
                "incorrect attestation subject"
            );
            let previous = if index == 0 {
                None
            } else {
                Some(digest(&self.attestations[index - 1])?)
            };
            ensure!(entry.previous == previous, "attestation chain mismatch");
            let key = VerifyingKey::from_bytes(&decode_hex::<32>(&entry.public_key)?)
                .context("invalid Ed25519 key")?;
            ensure!(
                role_keys
                    .get(&entry.role)
                    .is_some_and(|keys| keys.contains(&entry.public_key)),
                "key not authorized for {}",
                entry.role
            );
            let signature = Signature::from_bytes(&decode_hex::<64>(&entry.signature)?);
            let message = Message {
                domain: "anynix-release-attestation-v2",
                role: &entry.role,
                decision: &entry.decision,
                subject: &entry.subject,
                previous: &entry.previous,
                public_key: &entry.public_key,
            };
            let bytes = serde_json_canonicalizer::to_vec(&message)?;
            key.verify_strict(blake3::hash(&bytes).as_bytes(), &signature)
                .with_context(|| format!("invalid {} signature", entry.role))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hex;
    use ed25519_dalek::{Signer, SigningKey};

    fn example() -> (Envelope, BTreeMap<String, BTreeSet<String>>) {
        let content = SourceContent {
            payload: Blob {
                digest: blake3::hash(b"payload").to_hex().to_string(),
                size: 7,
            },
            build_script: Blob {
                digest: blake3::hash(b"script").to_hex().to_string(),
                size: 6,
            },
        };
        let source = Source {
            format: "anynix-source-v2".into(),
            package: "example".into(),
            version: "1.0.0".into(),
            source: content.clone(),
        };
        let release = Release {
            format: "anynix-release-v2".into(),
            package: "example".into(),
            version: "1.0.0".into(),
            license: Some("MIT".into()),
            source: content,
            sources: Vec::new(),
            targets: vec![Target::Success {
                os: "linux".into(),
                architecture: "x86_64".into(),
                dependencies: Vec::new(),
                files: vec![File {
                    digest: blake3::hash(b"binary").to_hex().to_string(),
                    size: 6,
                    install_path: "bin/example".into(),
                    permissions: 0o755,
                    file_type: FileType::Binary,
                }],
            }],
        };
        let mut envelope = Envelope {
            source,
            release,
            attestations: Vec::new(),
        };
        let mut policy = BTreeMap::new();
        for (index, role) in ROLES.iter().enumerate() {
            let key = SigningKey::from_bytes(&[(index + 1) as u8; 32]);
            let public_key = hex(key.verifying_key().as_bytes());
            policy.insert(role.to_string(), BTreeSet::from([public_key.clone()]));
            let previous = envelope
                .attestations
                .last()
                .map(|attestation| digest(attestation).unwrap());
            let subject = if index < 3 {
                digest(&envelope.source).unwrap()
            } else {
                digest(&envelope.release).unwrap()
            };
            let mut entry = Attestation {
                role: role.to_string(),
                decision: "Approve".into(),
                subject,
                previous,
                public_key,
                signature: String::new(),
            };
            let message = Message {
                domain: "anynix-release-attestation-v2",
                role: &entry.role,
                decision: &entry.decision,
                subject: &entry.subject,
                previous: &entry.previous,
                public_key: &entry.public_key,
            };
            let bytes = serde_json_canonicalizer::to_vec(&message).unwrap();
            entry.signature = hex(&key.sign(blake3::hash(&bytes).as_bytes()).to_bytes());
            envelope.attestations.push(entry);
        }
        (envelope, policy)
    }

    #[test]
    fn validates_signed_release_and_detects_changes() {
        let (mut envelope, policy) = example();
        envelope.verify_signatures(&policy).unwrap();
        envelope
            .source
            .verify_content(b"payload", b"script")
            .unwrap();
        assert!(
            envelope
                .source
                .verify_content(b"Payload", b"script")
                .is_err()
        );
        envelope.release.license = Some("GPL-3.0".into());
        assert!(envelope.verify_signatures(&policy).is_err());
        let (mut envelope, policy) = example();
        envelope.attestations[1].signature.replace_range(0..2, "00");
        assert!(envelope.verify_signatures(&policy).is_err());
    }

    #[test]
    fn rejects_bad_policy_and_missing_required_build() {
        let (envelope, mut policy) = example();
        policy.remove("Manager");
        assert!(envelope.verify_signatures(&policy).is_err());
        assert!(
            envelope
                .release
                .verify_required_targets(&BTreeSet::new())
                .is_err()
        );
        assert!(
            envelope
                .release
                .verify_required_targets(&BTreeSet::from([("freebsd".into(), "x86_64".into())]))
                .is_err()
        );
        assert!(
            envelope
                .release
                .verify_required_targets(&BTreeSet::from([("linux".into(), "x86_64".into())]))
                .is_ok()
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_missing_fields() {
        let (envelope, _) = example();
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(
            serde_json::from_str::<Envelope>(&json.replacen(
                "\"format\":",
                "\"extra\":0,\"format\":",
                1
            ))
            .is_err()
        );
        assert!(
            serde_json::from_str::<Envelope>(&json.replacen(
                "\"format\":",
                "\"format\":\"duplicate\",\"format\":",
                1
            ))
            .is_err()
        );
        assert!(
            serde_json::from_str::<Envelope>(&json.replacen("\"license\":\"MIT\",", "", 1))
                .is_err()
        );
        assert!(
            serde_json::from_str::<Envelope>(&json.replacen("\"previous\":null,", "", 1)).is_err()
        );
        assert!(
            serde_json::from_str::<Envelope>(&json.replacen(
                "\"os\":\"linux\"",
                "\"os\":\"linux\",\"os\":\"freebsd\"",
                1
            ))
            .is_err()
        );
    }

    #[test]
    fn rejects_unsafe_paths_and_duplicate_targets() {
        let (mut envelope, _) = example();
        if let Target::Success { files, .. } = &mut envelope.release.targets[0] {
            files[0].install_path = "../etc/passwd".into();
        }
        assert!(envelope.release.validate().is_err());
        let (mut envelope, _) = example();
        envelope
            .release
            .targets
            .push(envelope.release.targets[0].clone());
        assert!(envelope.release.validate().is_err());
    }

    #[test]
    fn canonicalizes_and_checks_blob_contents() {
        let value = serde_json::json!({"z": 1, "a": {"b": 2, "a": "ok"}});
        assert_eq!(
            serde_json_canonicalizer::to_string(&value).unwrap(),
            r#"{"a":{"a":"ok","b":2},"z":1}"#
        );
        let reference = Blob {
            digest: blake3::hash(b"payload").to_hex().to_string(),
            size: 7,
        };
        assert!(reference.verify_content(b"payload").is_ok());
        assert!(reference.verify_content(b"Payload").is_err());
        assert!(reference.verify_content(b"short").is_err());
    }
}
