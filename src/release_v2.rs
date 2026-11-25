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

pub(crate) fn package(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._+-".contains(&b))
}

pub(crate) fn version(value: &str) -> bool {
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
        let envelope = Envelope {
            source,
            release,
            attestations: Vec::new(),
        };
        sign_example(envelope)
    }

    fn sign_example(mut envelope: Envelope) -> (Envelope, BTreeMap<String, BTreeSet<String>>) {
        envelope.attestations.clear();
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

    #[tokio::test]
    async fn signed_release_is_authenticated_by_a_local_tuf_repository() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::Ed25519KeyPair;
        use futures_util::TryStreamExt;
        use jiff::{SignedDuration, Timestamp};
        use std::{collections::HashMap, num::NonZeroU64};
        use tough::{
            RepositoryLoader, TargetName,
            editor::{RepositoryEditor, signed::SignedRole},
            key_source::{KeySource, LocalKeySource},
            schema::{KeyHolder, RoleKeys, RoleType, Root, Target as TufTarget},
        };
        use url::Url;

        let directory = tempfile::tempdir().unwrap();
        let base = directory.path();
        let metadata_dir = base.join("metadata");
        let targets_dir = base.join("targets");
        let state_dir = base.join("state");
        let root_path = base.join("trusted-root.json");
        std::fs::create_dir_all(&metadata_dir).unwrap();
        std::fs::create_dir_all(&targets_dir).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();

        let mut keys: Vec<Box<dyn KeySource>> = Vec::new();
        for index in 0..4 {
            let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let path = base.join(format!("test-tuf-key-{index}.der"));
            std::fs::write(&path, key.as_ref()).unwrap();
            keys.push(Box::new(LocalKeySource { path }));
        }
        let mut public_keys = HashMap::new();
        let mut key_ids = Vec::new();
        for key in &keys {
            let public_key = key.as_sign().await.unwrap().tuf_key();
            let key_id = public_key.key_id().unwrap();
            public_keys.insert(key_id.clone(), public_key);
            key_ids.push(key_id);
        }
        let root_keys = RoleKeys {
            keyids: key_ids[..3].to_vec(),
            threshold: NonZeroU64::new(2).unwrap(),
            _extra: Default::default(),
        };
        let online_key = RoleKeys {
            keyids: vec![key_ids[3].clone()],
            threshold: NonZeroU64::new(1).unwrap(),
            _extra: Default::default(),
        };
        let expires = Timestamp::now() + SignedDuration::from_secs(86_400);
        let root = Root {
            spec_version: "1.0.0".into(),
            consistent_snapshot: false,
            version: NonZeroU64::new(1).unwrap(),
            expires,
            keys: public_keys,
            roles: HashMap::from([
                (RoleType::Root, root_keys),
                (RoleType::Targets, online_key.clone()),
                (RoleType::Snapshot, online_key.clone()),
                (RoleType::Timestamp, online_key),
            ]),
            _extra: HashMap::new(),
        };
        let signed_root = SignedRole::new(
            root.clone(),
            &KeyHolder::Root(root),
            &keys[..2],
            &SystemRandom::new(),
        )
        .await
        .unwrap();
        std::fs::write(&root_path, signed_root.buffer()).unwrap();

        let (mut envelope, _) = example();
        if let Target::Success { dependencies, .. } = &mut envelope.release.targets[0] {
            dependencies.push(Dependency {
                package: "helper".into(),
                version: "1.0.0".into(),
            });
        }
        let (envelope, policy) = sign_example(envelope);
        let (mut helper, _) = example();
        helper.source.package = "helper".into();
        helper.release.package = "helper".into();
        if let Target::Success { files, .. } = &mut helper.release.targets[0] {
            files[0].digest = blake3::hash(b"library").to_hex().to_string();
            files[0].size = 7;
            files[0].install_path = "lib/helper".into();
            files[0].permissions = 0o644;
        }
        let (helper, _) = sign_example(helper);
        let (mut cyclic, _) = example();
        cyclic.source.package = "cyclic".into();
        cyclic.release.package = "cyclic".into();
        if let Target::Success { dependencies, .. } = &mut cyclic.release.targets[0] {
            dependencies.push(Dependency {
                package: "cyclic".into(),
                version: "1.0.0".into(),
            });
        }
        let (cyclic, _) = sign_example(cyclic);
        let blob_dir = base.join("blobs");
        std::fs::create_dir(&blob_dir).unwrap();
        let blob_bytes = b"binary";
        let blob_path = blob_dir.join(blake3::hash(blob_bytes).to_hex().as_str());
        std::fs::write(&blob_path, blob_bytes).unwrap();
        let helper_blob_path = blob_dir.join(blake3::hash(b"library").to_hex().as_str());
        std::fs::write(&helper_blob_path, b"library").unwrap();
        let policy_data = serde_json::json!({
            "format": "anynix-attestation-keys-v1",
            "roles": policy
        });
        let index_data = serde_json::json!({
            "format": "anynix-package-index-v1",
            "package": "example",
            "latest": "1.0.0",
            "versions": ["1.0.0"]
        });
        let helper_index = serde_json::json!({
            "format": "anynix-package-index-v1",
            "package": "helper",
            "latest": "1.0.0",
            "versions": ["1.0.0"]
        });
        let cyclic_index = serde_json::json!({
            "format": "anynix-package-index-v1",
            "package": "cyclic",
            "latest": "1.0.0",
            "versions": ["1.0.0"]
        });
        let files = [
            (
                "anynix/attestation-keys.json",
                serde_json::to_vec(&policy_data).unwrap(),
            ),
            (
                "anynix/packages/example.json",
                serde_json::to_vec(&index_data).unwrap(),
            ),
            (
                "anynix/releases/example/1.0.0.json",
                serde_json::to_vec(&envelope).unwrap(),
            ),
            (
                "anynix/packages/helper.json",
                serde_json::to_vec(&helper_index).unwrap(),
            ),
            (
                "anynix/releases/helper/1.0.0.json",
                serde_json::to_vec(&helper).unwrap(),
            ),
            (
                "anynix/packages/cyclic.json",
                serde_json::to_vec(&cyclic_index).unwrap(),
            ),
            (
                "anynix/releases/cyclic/1.0.0.json",
                serde_json::to_vec(&cyclic).unwrap(),
            ),
        ];
        let mut editor = RepositoryEditor::new(&root_path).await.unwrap();
        let version = NonZeroU64::new(1).unwrap();
        editor.snapshot_version(version).snapshot_expires(expires);
        editor.timestamp_version(version).timestamp_expires(expires);
        editor.targets_version(version).unwrap();
        editor.targets_expires(expires).unwrap();
        for (name, bytes) in &files {
            let path = targets_dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            editor
                .add_target(*name, TufTarget::from_path(&path).await.unwrap())
                .unwrap();
        }
        editor
            .sign(&keys[3..])
            .await
            .unwrap()
            .write(&metadata_dir)
            .await
            .unwrap();

        let root_bytes = std::fs::read(&root_path).unwrap();
        let metadata_url = Url::from_directory_path(&metadata_dir).unwrap();
        let targets_url = Url::from_directory_path(&targets_dir).unwrap();
        let repo = RepositoryLoader::new(&root_bytes, metadata_url.clone(), targets_url.clone())
            .datastore(&state_dir)
            .load()
            .await
            .unwrap();
        let mut authenticated = Vec::new();
        for (name, _) in &files {
            let stream = repo
                .read_target(&TargetName::new(*name).unwrap())
                .await
                .unwrap()
                .unwrap();
            let chunks: Vec<_> = stream.try_collect().await.unwrap();
            authenticated.push(chunks.into_iter().flatten().collect::<Vec<_>>());
        }
        let authenticated_policy: serde_json::Value =
            serde_json::from_slice(&authenticated[0]).unwrap();
        let role_keys = serde_json::from_value(authenticated_policy["roles"].clone()).unwrap();
        let authenticated_release: Envelope = serde_json::from_slice(&authenticated[2]).unwrap();
        authenticated_release.verify_signatures(&role_keys).unwrap();
        if std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64" {
            let install_state = base.join("install-state");
            let prefix = base.join("apps");
            std::fs::create_dir(&install_state).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&install_state, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            use clap::Parser;
            let args = [
                "anynix",
                "install",
                "example",
                "--repository",
                base.to_str().unwrap(),
                "--trust-root",
                root_path.to_str().unwrap(),
                "--state",
                install_state.to_str().unwrap(),
                "--prefix",
                prefix.to_str().unwrap(),
            ];
            let command = crate::cli::Cli::try_parse_from(args).unwrap().command;
            crate::execute(command).await.unwrap();
            assert_eq!(
                std::fs::read(prefix.join("bin/example")).unwrap(),
                blob_bytes
            );
            assert_eq!(
                std::fs::read(prefix.join("lib/helper")).unwrap(),
                b"library"
            );
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(prefix.join("bin/example"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
            assert!(
                crate::install::install("example@1.0.0", base, &root_path, &install_state, &prefix)
                    .await
                    .is_err()
            );
            assert_eq!(
                std::fs::read(prefix.join("bin/example")).unwrap(),
                blob_bytes
            );
            std::fs::write(&blob_path, b"tamper").unwrap();
            let other_prefix = base.join("other-apps");
            assert!(
                crate::install::install("example", base, &root_path, &install_state, &other_prefix)
                    .await
                    .is_err()
            );
            assert!(!other_prefix.exists());
            std::fs::write(&blob_path, blob_bytes).unwrap();
            std::fs::remove_file(targets_dir.join("anynix/releases/helper/1.0.0.json")).unwrap();
            let missing_prefix = base.join("missing-dependency");
            assert!(
                crate::install::install(
                    "example",
                    base,
                    &root_path,
                    &install_state,
                    &missing_prefix
                )
                .await
                .is_err()
            );
            assert!(!missing_prefix.exists());
            std::fs::write(targets_dir.join(files[4].0), &files[4].1).unwrap();
            let cycle_prefix = base.join("cycle");
            let error =
                crate::install::install("cyclic", base, &root_path, &install_state, &cycle_prefix)
                    .await
                    .unwrap_err();
            assert!(error.to_string().contains("dependency cycle"));
            assert!(!cycle_prefix.exists());
        }
        if let Target::Success { files, .. } = &authenticated_release.release.targets[0] {
            let file = &files[0];
            let blob = Blob {
                digest: file.digest.clone(),
                size: file.size,
            };
            blob.verify_content(&std::fs::read(&blob_path).unwrap())
                .unwrap();
            std::fs::write(&blob_path, b"tamper").unwrap();
            assert!(
                blob.verify_content(&std::fs::read(&blob_path).unwrap())
                    .is_err()
            );
        } else {
            panic!("test release target must succeed");
        }
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&authenticated[1]).unwrap(),
            index_data
        );

        let release_path = targets_dir.join(files[2].0);
        std::fs::write(&release_path, b"tampered").unwrap();
        let stream = repo
            .read_target(&TargetName::new(files[2].0).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(stream.try_collect::<Vec<_>>().await.is_err());
        if std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64" {
            let prefix = base.join("tampered-release");
            assert!(
                crate::install::install(
                    "example",
                    base,
                    &root_path,
                    &base.join("install-state"),
                    &prefix
                )
                .await
                .is_err()
            );
            assert!(!prefix.exists());
        }

        let mut incomplete_root: serde_json::Value = serde_json::from_slice(&root_bytes).unwrap();
        incomplete_root["signatures"]
            .as_array_mut()
            .unwrap()
            .truncate(1);
        let bad_root = serde_json::to_vec(&incomplete_root).unwrap();
        assert!(
            RepositoryLoader::new(&bad_root, metadata_url, targets_url)
                .load()
                .await
                .is_err()
        );

        let expired_metadata = base.join("expired-metadata");
        std::fs::create_dir(&expired_metadata).unwrap();
        let mut expired_editor = RepositoryEditor::new(&root_path).await.unwrap();
        expired_editor
            .snapshot_version(version)
            .snapshot_expires(expires);
        expired_editor
            .timestamp_version(version)
            .timestamp_expires(Timestamp::now() - SignedDuration::from_secs(60));
        expired_editor.targets_version(version).unwrap();
        expired_editor.targets_expires(expires).unwrap();
        for (name, bytes) in &files {
            let path = targets_dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            expired_editor
                .add_target(*name, TufTarget::from_path(&path).await.unwrap())
                .unwrap();
        }
        expired_editor
            .sign(&keys[3..])
            .await
            .unwrap()
            .write(&expired_metadata)
            .await
            .unwrap();
        let expired = RepositoryLoader::new(
            &root_bytes,
            Url::from_directory_path(&expired_metadata).unwrap(),
            Url::from_directory_path(&targets_dir).unwrap(),
        )
        .load()
        .await
        .unwrap_err();
        assert!(expired.to_string().to_lowercase().contains("expir"));
        if std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64" {
            let expired_repo = base.join("expired-repo");
            std::fs::create_dir(&expired_repo).unwrap();
            std::fs::rename(&expired_metadata, expired_repo.join("metadata")).unwrap();
            std::fs::create_dir(expired_repo.join("targets")).unwrap();
            let expired_state = base.join("expired-state");
            std::fs::create_dir(&expired_state).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&expired_state, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let prefix = base.join("expired-apps");
            assert!(
                crate::install::install(
                    "example",
                    &expired_repo,
                    &root_path,
                    &expired_state,
                    &prefix
                )
                .await
                .is_err()
            );
            assert!(!prefix.exists());
        }
    }
}
