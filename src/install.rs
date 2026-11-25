use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use futures_util::TryStreamExt;
use rustix::{
    fs::{self as rfs, AtFlags, FlockOperation, Mode, OFlags},
    io::Errno,
};
use serde::Deserialize;
use tough::{
    FilesystemTransport, Repository, RepositoryLoader, TargetName,
    schema::{Root, Signed},
};
use url::Url;

use crate::release_v2::{self, Envelope, Target};

const MAX_METADATA: usize = 4 * 1024 * 1024;
const MAX_FILE: u64 = 256 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
const MAX_FILES: usize = 1024;
const MAX_PACKAGES: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    format: String,
    roles: Roles,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct Roles {
    Developer: Vec<String>,
    Reviewer: Vec<String>,
    Manager: Vec<String>,
    BuildServer: Vec<String>,
    ReleaseAuthority: Vec<String>,
}

impl Roles {
    fn into_keys(self) -> Result<BTreeMap<String, BTreeSet<String>>> {
        let mut result = BTreeMap::new();
        for (role, keys) in [
            ("Developer", self.Developer),
            ("Reviewer", self.Reviewer),
            ("Manager", self.Manager),
            ("BuildServer", self.BuildServer),
            ("ReleaseAuthority", self.ReleaseAuthority),
        ] {
            let len = keys.len();
            let keys: BTreeSet<_> = keys.into_iter().collect();
            ensure!(len == keys.len(), "duplicate key in {role} policy");
            result.insert(role.to_string(), keys);
        }
        Ok(result)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    format: String,
    package: String,
    latest: String,
    versions: Vec<String>,
}

struct StagedFile {
    path: String,
    permissions: u32,
    staged: PathBuf,
}

fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "{} exceeds size limit",
        path.display()
    );
    Ok(bytes)
}

fn protected_directory(path: &Path, private: bool, current_user_only: bool) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut directory = rfs::open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let uid = rustix::process::geteuid().as_raw();
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                directory = rfs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .with_context(|| format!("opening protected directory {}", path.display()))?;
                let stat = rfs::fstat(&directory)?;
                ensure!(
                    (stat.st_uid == 0 || stat.st_uid == uid)
                        && (stat.st_mode & 0o022 == 0 || stat.st_mode & 0o1000 != 0),
                    "untrusted ancestor of {}",
                    path.display()
                );
            }
            _ => bail!("directory path contains a parent component"),
        }
    }
    let stat = rfs::fstat(&directory)?;
    let owner_ok = stat.st_uid == uid || (!current_user_only && stat.st_uid == 0);
    let permissions_ok = if private {
        stat.st_mode & 0o077 == 0
    } else {
        stat.st_mode & 0o022 == 0 || (!current_user_only && stat.st_mode & 0o1000 != 0)
    };
    ensure!(
        owner_ok && permissions_ok,
        "directory {} is not protected",
        path.display()
    );
    Ok(())
}

fn private_state(state: &Path) -> Result<File> {
    protected_directory(state, true, true)?;
    let metadata = fs::symlink_metadata(state).context("opening TUF state directory")?;
    ensure!(
        metadata.is_dir(),
        "TUF state must be a directory, not a link"
    );
    ensure!(
        metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o077 == 0,
        "TUF state directory must be owned by the current user and private"
    );
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(state.join("lock"))
        .context("opening TUF state lock")?;
    rfs::flock(&lock, FlockOperation::LockExclusive)?;
    Ok(lock)
}

async fn load_repository(repo: &Path, root_path: &Path, state: &Path) -> Result<Repository> {
    let parent = root_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // The independently trusted root must not be replaceable by other users.
    protected_directory(parent, false, false)?;
    let root_file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(root_path)
        .context("opening trusted root")?;
    let root_metadata = root_file.metadata()?;
    ensure!(
        root_metadata.is_file()
            && (root_metadata.uid() == rustix::process::geteuid().as_raw()
                || root_metadata.uid() == 0)
            && root_metadata.mode() & 0o022 == 0,
        "trusted root must be a protected regular file owned by the current user or root"
    );
    let mut anchor = Vec::new();
    root_file
        .take(MAX_METADATA as u64 + 1)
        .read_to_end(&mut anchor)?;
    ensure!(
        anchor.len() <= MAX_METADATA,
        "trusted root exceeds size limit"
    );
    let parsed: Signed<Root> = serde_json::from_slice(&anchor).context("invalid trusted root")?;
    let root_role = parsed
        .signed
        .roles
        .get(&tough::schema::RoleType::Root)
        .context("missing root role")?;
    let unique: BTreeSet<_> = root_role.keyids.iter().collect();
    ensure!(
        root_role.threshold.get() == 2 && root_role.keyids.len() == 3 && unique.len() == 3,
        "initial TUF root must have three distinct keys and a threshold of two"
    );
    parsed
        .signed
        .verify_role(&parsed)
        .context("invalid trusted root signatures")?;
    let anchor_digest = blake3::hash(&anchor).to_hex().to_string();
    let marker = state.join("anchor");
    if marker.exists() {
        ensure!(
            read_limited(&marker, 64)? == anchor_digest.as_bytes(),
            "TUF state belongs to another trust root"
        );
    } else {
        ensure!(
            !state.join("root.json").exists(),
            "TUF state has no trust anchor"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&marker)?;
        file.write_all(anchor_digest.as_bytes())?;
        file.sync_all()?;
    }
    let saved_root = state.join("root.json");
    let trusted = if saved_root.exists() {
        read_limited(&saved_root, MAX_METADATA as u64)?
    } else {
        anchor
    };
    let repo = fs::canonicalize(repo).context("opening local repository")?;
    let metadata_url = Url::from_directory_path(repo.join("metadata"))
        .map_err(|_| anyhow::anyhow!("invalid metadata directory"))?;
    let targets_url = Url::from_directory_path(repo.join("targets"))
        .map_err(|_| anyhow::anyhow!("invalid targets directory"))?;
    RepositoryLoader::new(&trusted, metadata_url, targets_url)
        .transport(FilesystemTransport)
        .datastore(state)
        .load()
        .await
        .context("verifying TUF metadata")
}

async fn target(repo: &Repository, name: &str) -> Result<Vec<u8>> {
    let name = TargetName::new(name)?;
    let mut stream = repo
        .read_target(&name)
        .await?
        .context("missing authenticated TUF target")?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.try_next().await? {
        ensure!(
            bytes.len() + chunk.len() <= MAX_METADATA,
            "TUF target exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn resolve(repo: &Repository, request: &str) -> Result<Vec<release_v2::File>> {
    let (name, requested_version) = match request.split_once('@') {
        Some((name, version)) => (name, Some(version)),
        None => (request, None),
    };
    ensure!(release_v2::package(name), "invalid package name");
    if let Some(version) = requested_version {
        ensure!(release_v2::version(version), "invalid package version");
    }
    let policy: Policy =
        serde_json::from_slice(&target(repo, "anynix/attestation-keys.json").await?)?;
    ensure!(
        policy.format == "anynix-attestation-keys-v1",
        "unsupported key policy"
    );
    let keys = policy.roles.into_keys()?;
    ensure!(
        repo.targets()
            .signed
            .delegations
            .as_ref()
            .is_none_or(|delegations| delegations.roles.is_empty() && delegations.keys.is_empty()),
        "delegated TUF targets are not supported"
    );
    for key in repo.root().signed.keys.values() {
        if let tough::schema::key::Key::Ed25519 { keyval, .. } = key {
            let public_key = crate::crypto::hex(keyval.public.as_ref());
            ensure!(
                !keys.values().any(|role| role.contains(&public_key)),
                "TUF and attestation keys must be distinct"
            );
        }
    }
    let mut pending = vec![(name.to_owned(), requested_version.map(str::to_owned), false)];
    let mut selected = BTreeMap::<String, String>::new();
    let mut visiting = BTreeSet::new();
    let mut done = BTreeSet::new();
    let mut files = Vec::new();
    while let Some((name, version, leaving)) = pending.pop() {
        if leaving {
            visiting.remove(&name);
            done.insert(name);
            continue;
        }
        ensure!(
            !visiting.contains(&name),
            "dependency cycle involving {name}"
        );
        if let Some(existing) = selected.get(&name) {
            if let Some(version) = &version {
                ensure!(existing == version, "conflicting versions for {name}");
            }
            if done.contains(&name) {
                continue;
            }
        }
        let index: Index =
            serde_json::from_slice(&target(repo, &format!("anynix/packages/{name}.json")).await?)?;
        ensure!(
            index.format == "anynix-package-index-v1" && index.package == name,
            "invalid package index"
        );
        let versions: BTreeSet<_> = index.versions.iter().collect();
        ensure!(
            !versions.is_empty()
                && versions.len() == index.versions.len()
                && index.versions.iter().all(|v| release_v2::version(v))
                && versions.contains(&index.latest),
            "invalid package versions"
        );
        let version = version.unwrap_or(index.latest);
        ensure!(
            versions.contains(&version),
            "version {name}@{version} not in authenticated index"
        );
        let envelope: Envelope = serde_json::from_slice(
            &target(repo, &format!("anynix/releases/{name}/{version}.json")).await?,
        )?;
        envelope.verify_signatures(&keys)?;
        ensure!(
            envelope.release.package == name && envelope.release.version == version,
            "release identity mismatch"
        );
        let target = envelope
            .release
            .targets
            .into_iter()
            .find(|target| match target {
                Target::Success {
                    os, architecture, ..
                }
                | Target::Failed {
                    os, architecture, ..
                } => os == std::env::consts::OS && architecture == std::env::consts::ARCH,
            })
            .context("release has no target for this system")?;
        let Target::Success {
            dependencies,
            files: target_files,
            ..
        } = target
        else {
            bail!("build failed for the current system");
        };
        selected.insert(name.clone(), version);
        ensure!(selected.len() <= MAX_PACKAGES, "too many dependencies");
        visiting.insert(name.clone());
        pending.push((name, None, true));
        for dependency in dependencies.into_iter().rev() {
            pending.push((dependency.package, Some(dependency.version), false));
        }
        files.extend(target_files);
        ensure!(files.len() <= MAX_FILES, "too many files");
    }
    validate_paths(&files)?;
    Ok(files)
}

fn validate_paths(files: &[release_v2::File]) -> Result<()> {
    let paths: BTreeSet<_> = files
        .iter()
        .map(|file| file.install_path.as_str())
        .collect();
    ensure!(paths.len() == files.len(), "conflicting installation paths");
    for path in &paths {
        for (index, _) in path.match_indices('/') {
            ensure!(
                !paths.contains(&path[..index]),
                "file conflicts with a parent directory"
            );
        }
    }
    Ok(())
}

fn stage(repo: &Path, files: &[release_v2::File], dir: &Path) -> Result<Vec<StagedFile>> {
    let mut total = 0u64;
    let mut staged = Vec::new();
    for (index, file) in files.iter().enumerate() {
        ensure!(file.size <= MAX_FILE, "blob exceeds size limit");
        total = total
            .checked_add(file.size)
            .context("total size overflow")?;
        ensure!(total <= MAX_TOTAL, "installation exceeds size limit");
        let source = repo.join("blobs").join(&file.digest);
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&source)
            .with_context(|| format!("opening blob {}", file.digest))?;
        ensure!(input.metadata()?.is_file(), "blob must be a regular file");
        let path = dir.join(index.to_string());
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let mut hasher = blake3::Hasher::new();
        let mut size = 0u64;
        let mut buffer = [0; 65536];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            size += read as u64;
            ensure!(size <= file.size, "blob size mismatch");
            hasher.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
        }
        ensure!(
            size == file.size && hasher.finalize().to_hex().as_str() == file.digest,
            "blob integrity mismatch"
        );
        staged.push(StagedFile {
            path: file.install_path.clone(),
            permissions: file.permissions as u32,
            staged: path,
        });
    }
    Ok(staged)
}

fn install_files(prefix: &Path, files: &[StagedFile]) -> Result<()> {
    if !prefix.exists() {
        let parent = prefix
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        protected_directory(parent, false, false)?;
        fs::DirBuilder::new()
            .mode(0o755)
            .create(prefix)
            .with_context(|| format!("creating {}", prefix.display()))?;
    }
    protected_directory(prefix, false, true)?;
    let root = rfs::open(
        prefix,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = rfs::fstat(&root)?;
    ensure!(
        stat.st_uid == rustix::process::geteuid().as_raw() && stat.st_mode & 0o022 == 0,
        "installation prefix must be owned by the current user and not writable by others"
    );
    for entry in files {
        let mut parent = rustix::io::dup(&root)?;
        let mut parts = entry.path.split('/').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                match rfs::statat(&parent, part, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(_) => bail!("refusing to overwrite {}", entry.path),
                    Err(Errno::NOENT) => {}
                    Err(error) => return Err(error.into()),
                }
            } else {
                match rfs::openat(
                    &parent,
                    part,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
                    Ok(directory) => {
                        let stat = rfs::fstat(&directory)?;
                        ensure!(
                            stat.st_uid == rustix::process::geteuid().as_raw()
                                && stat.st_mode & 0o022 == 0,
                            "unsafe installation directory"
                        );
                        parent = directory;
                    }
                    Err(Errno::NOENT) => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    let mut created_files = Vec::new();
    let mut created_dirs = Vec::new();
    let result = (|| -> Result<()> {
        for entry in files {
            let mut parent = rustix::io::dup(&root)?;
            let mut parts = entry.path.split('/').peekable();
            while let Some(part) = parts.next() {
                if parts.peek().is_none() {
                    let rollback_parent = rustix::io::dup(&parent)?;
                    let fd = rfs::openat(
                        &parent,
                        part,
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::from_bits_truncate(0o600),
                    )
                    .with_context(|| format!("refusing to overwrite {}", entry.path))?;
                    created_files.push((rollback_parent, part.to_string()));
                    let mut output = File::from(fd);
                    std::io::copy(&mut File::open(&entry.staged)?, &mut output)?;
                    rfs::fchmod(&output, Mode::from_bits_truncate(entry.permissions))?;
                    output.sync_all()?;
                } else {
                    let rollback_parent = rustix::io::dup(&parent)?;
                    match rfs::mkdirat(&parent, part, Mode::from_bits_truncate(0o755)) {
                        Ok(()) => created_dirs.push((rollback_parent, part.to_string())),
                        Err(Errno::EXIST) => {}
                        Err(error) => return Err(error.into()),
                    }
                    parent = rfs::openat(
                        &parent,
                        part,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?;
                    let stat = rfs::fstat(&parent)?;
                    ensure!(
                        stat.st_uid == rustix::process::geteuid().as_raw()
                            && stat.st_mode & 0o022 == 0,
                        "unsafe installation directory"
                    );
                }
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        let mut cleanup_errors = Vec::new();
        for (parent, name) in created_files.iter().rev() {
            if let Err(failure) = rfs::unlinkat(parent, name.as_str(), AtFlags::empty()) {
                cleanup_errors.push(format!("{name}: {failure}"));
            }
        }
        for (parent, name) in created_dirs.iter().rev() {
            if let Err(failure) = rfs::unlinkat(parent, name.as_str(), AtFlags::REMOVEDIR) {
                cleanup_errors.push(format!("{name}: {failure}"));
            }
        }
        if !cleanup_errors.is_empty() {
            bail!("{error:#}; rollback failed: {}", cleanup_errors.join(", "));
        }
        return Err(error);
    }
    Ok(())
}

pub async fn install(
    request: &str,
    repo: &Path,
    root: &Path,
    state: &Path,
    prefix: &Path,
) -> Result<()> {
    let _lock = private_state(state)?;
    let repository = load_repository(repo, root, state).await?;
    let files = resolve(&repository, request).await?;
    let temporary = tempfile::tempdir()?;
    let staged = stage(repo, &files, temporary.path())?;
    target(&repository, "anynix/attestation-keys.json").await?;
    install_files(prefix, &staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn refuses_untrusted_state_ancestors() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("untrusted");
        let state = parent.join("state");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(private_state(&state).is_err());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let link = temp.path().join("link");
        symlink(&parent, &link).unwrap();
        assert!(private_state(&link.join("state")).is_err());
    }

    #[test]
    fn detects_file_and_parent_conflicts_even_with_intervening_names() {
        let files = ["a", "a-", "a/b"].map(|path| release_v2::File {
            digest: "0".repeat(64),
            size: 0,
            install_path: path.into(),
            permissions: 0o644,
            file_type: release_v2::FileType::Binary,
        });
        assert!(validate_paths(&files).is_err());
    }

    #[test]
    fn refuses_links_before_copying_files() {
        let temp = tempfile::tempdir().unwrap();
        let prefix = temp.path().join("apps");
        let outside = temp.path().join("outside");
        fs::create_dir(&prefix).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, prefix.join("bin")).unwrap();
        let source = temp.path().join("source");
        fs::write(&source, b"example").unwrap();
        let files = vec![
            StagedFile {
                path: "lib/example".into(),
                permissions: 0o644,
                staged: source.clone(),
            },
            StagedFile {
                path: "bin/example".into(),
                permissions: 0o755,
                staged: source,
            },
        ];
        assert!(install_files(&prefix, &files).is_err());
        assert!(!prefix.join("lib").exists());
        assert!(!outside.join("example").exists());
    }

    #[test]
    fn leaves_existing_file_untouched() {
        let temp = tempfile::tempdir().unwrap();
        let prefix = temp.path().join("apps");
        fs::create_dir(&prefix).unwrap();
        fs::write(prefix.join("existing"), b"original").unwrap();
        let source = temp.path().join("source");
        fs::write(&source, b"new").unwrap();
        let files = vec![
            StagedFile {
                path: "new".into(),
                permissions: 0o644,
                staged: source.clone(),
            },
            StagedFile {
                path: "existing".into(),
                permissions: 0o644,
                staged: source,
            },
        ];
        assert!(install_files(&prefix, &files).is_err());
        assert!(!prefix.join("new").exists());
        assert_eq!(fs::read(prefix.join("existing")).unwrap(), b"original");
    }

    #[test]
    fn rolls_back_after_a_copy_failure() {
        let temp = tempfile::tempdir().unwrap();
        let prefix = temp.path().join("apps");
        fs::create_dir(&prefix).unwrap();
        let source = temp.path().join("source");
        fs::write(&source, b"new").unwrap();
        let files = vec![
            StagedFile {
                path: "lib/new".into(),
                permissions: 0o644,
                staged: source,
            },
            StagedFile {
                path: "bin/fails".into(),
                permissions: 0o644,
                staged: temp.path().join("missing"),
            },
        ];
        assert!(install_files(&prefix, &files).is_err());
        assert!(!prefix.join("lib").exists());
        assert!(!prefix.join("bin").exists());
    }
}
