use crate::crypto::{self, Decision, Manifest, Role};
use anyhow::{Context, Result, bail, ensure};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Cursor, Read, Write},
    path::{Component, Path, PathBuf},
};

const MAX_COMPRESSED: u64 = 256 * 1024 * 1024;
const MAX_EXPANDED: u64 = 512 * 1024 * 1024;
const MAX_SCRIPT: u64 = 1024 * 1024;
const MAX_MANIFEST: u64 = 1024 * 1024;

pub struct Package {
    payload: Vec<u8>,
    script: Vec<u8>,
    pub manifest: Manifest,
}

fn read_limited(reader: impl Read, max: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(max + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= max, "archive size limit exceeded");
    Ok(bytes)
}

fn decompress(bytes: &[u8], max: u64) -> Result<Vec<u8>> {
    read_limited(
        zstd::Decoder::new(bytes).context("invalid zstd stream")?,
        max,
    )
}

fn append_file<W: Write>(
    tar: &mut tar::Builder<W>,
    name: &str,
    data: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    tar.append_data(&mut header, name, data)?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    include: Vec<String>,
}

fn selection(root: &Path) -> Result<GlobSet> {
    let path = root.join("anynix.yaml");
    let bytes = read_limited(
        File::open(&path).with_context(|| format!("opening required {}", path.display()))?,
        MAX_MANIFEST,
    )?;
    let config: Selection = serde_yaml_ng::from_slice(&bytes).context("invalid anynix.yaml")?;
    ensure!(
        !config.include.is_empty(),
        "anynix.yaml include must not be empty"
    );
    let mut patterns = GlobSetBuilder::new();
    for pattern in config.include {
        ensure!(
            !pattern.is_empty()
                && Path::new(&pattern)
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "include pattern must be a relative path without . or ..: {pattern}"
        );
        patterns.add(
            GlobBuilder::new(&pattern)
                .literal_separator(true)
                .build()
                .with_context(|| format!("invalid include pattern: {pattern}"))?,
        );
    }
    Ok(patterns.build()?)
}

fn source_dir<W: Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    patterns: &GlobSet,
) -> Result<()> {
    let mut walker = WalkBuilder::new(root);
    walker
        .hidden(false)
        .parents(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(false)
        .require_git(false)
        .follow_links(false)
        .sort_by_file_path(|a, b| a.cmp(b))
        .filter_entry(|entry| entry.depth() == 0 || entry.file_name() != ".git");
    let mut selected = 0usize;
    for entry in walker.build() {
        let entry = entry.context("walking source directory")?;
        if let Some(error) = entry.error() {
            bail!("invalid ignore rules: {error}");
        }
        if entry.depth() == 0 {
            continue;
        }
        let rel = entry.path().strip_prefix(root)?;
        if !rel
            .ancestors()
            .any(|path| !path.as_os_str().is_empty() && patterns.is_match(path))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        selected += 1;
        if metadata.is_dir() {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder.append_data(&mut header, rel, std::io::empty())?;
        } else if metadata.is_file() {
            ensure!(
                metadata.len() <= MAX_EXPANDED,
                "source file too large: {}",
                rel.display()
            );
            let mut header = tar::Header::new_gnu();
            header.set_size(metadata.len());
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o777
            };
            #[cfg(not(unix))]
            let mode = 0o644;
            header.set_mode(mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder.append_data(&mut header, rel, File::open(entry.path())?)?;
        } else {
            bail!(
                "source contains unsupported link or special file: {}",
                rel.display()
            );
        }
    }
    ensure!(
        selected > 0,
        "include patterns selected no files or directories"
    );
    Ok(())
}

pub fn pack(path: &Path, script_path: &Path, key_path: &Path, output: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "source must be a directory, not a symlink"
    );
    let patterns = selection(path)?;
    let script = read_limited(File::open(script_path)?, MAX_SCRIPT)?;
    std::str::from_utf8(&script).context("build script must be UTF-8")?;
    let encoder = zstd::Encoder::new(Vec::new(), 3)?;
    let mut builder = tar::Builder::new(encoder);
    source_dir(&mut builder, path, &patterns)?;
    let payload = builder.into_inner()?.finish()?;
    ensure!(
        payload.len() as u64 <= MAX_COMPRESSED,
        "compressed payload too large"
    );
    // Validate the expanded payload before creating an archive that cannot later be unpacked.
    let expanded = decompress(&payload, MAX_EXPANDED)?;
    validate_payload(&expanded, None)?;
    let mut manifest = Manifest::new(&payload, &script);
    manifest.sign(
        Role::Developer,
        Decision::Approve,
        None,
        BTreeMap::new(),
        &crypto::load_key(key_path)?,
    )?;
    Package {
        payload,
        script,
        manifest,
    }
    .write(output, false)
}

impl Package {
    pub fn read(path: &Path) -> Result<Self> {
        let compressed = read_limited(
            File::open(path).with_context(|| format!("opening {}", path.display()))?,
            MAX_COMPRESSED,
        )?;
        let expanded = decompress(&compressed, MAX_EXPANDED)?;
        let mut archive = tar::Archive::new(Cursor::new(expanded));
        let (mut payload, mut script, mut manifest) = (None, None, None);
        for item in archive.entries()? {
            let mut entry = item?;
            ensure!(
                entry.header().entry_type().is_file(),
                "outer archive contains a non-file entry"
            );
            let path = entry.path()?.into_owned();
            let (slot, max) = match path.to_str() {
                Some("payload.tar.zst") => (&mut payload, MAX_COMPRESSED),
                Some("build.script") => (&mut script, MAX_SCRIPT),
                Some("manifest.json") => (&mut manifest, MAX_MANIFEST),
                _ => bail!("unexpected outer archive entry: {}", path.display()),
            };
            ensure!(
                slot.is_none(),
                "duplicate outer archive entry: {}",
                path.display()
            );
            *slot = Some(read_limited(&mut entry, max)?);
        }
        let payload = payload.context("missing payload.tar.zst")?;
        let script = script.context("missing build.script")?;
        std::str::from_utf8(&script).context("build script must be UTF-8")?;
        let manifest = serde_json::from_slice(&manifest.context("missing manifest.json")?)
            .context("invalid manifest")?;
        Ok(Self {
            payload,
            script,
            manifest,
        })
    }

    pub fn verify(&self, trust: &Path) -> Result<()> {
        self.manifest.verify(&self.payload, &self.script, trust)
    }

    pub fn validate_for_review(&self) -> Result<()> {
        let expanded = decompress(&self.payload, MAX_EXPANDED)?;
        validate_payload(&expanded, None)
    }

    pub fn ensure_not_rejected(&self) -> Result<()> {
        ensure!(
            self.manifest
                .attestations
                .last()
                .is_some_and(|entry| entry.decision == Decision::Approve),
            "package was rejected"
        );
        Ok(())
    }

    pub fn ensure_stage(&self, role: Role) -> Result<()> {
        self.ensure_not_rejected()?;
        ensure!(
            self.manifest
                .attestations
                .last()
                .is_some_and(|entry| entry.role == role),
            "expected package at {:?} stage",
            role
        );
        Ok(())
    }

    pub fn attest(
        &mut self,
        role: Role,
        decision: Decision,
        reason: Option<String>,
        key_path: &Path,
        trust: &Path,
    ) -> Result<()> {
        let key = crypto::load_key(key_path)?;
        crypto::ensure_trusted_signer(role, &key, trust)?;
        self.manifest
            .sign(role, decision, reason, BTreeMap::new(), &key)
    }

    pub fn write_replace(&self, path: &Path) -> Result<()> {
        self.write(path, true)
    }

    fn write(&self, path: &Path, replace: bool) -> Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        {
            let encoder = zstd::Encoder::new(temp.as_file_mut(), 3)?;
            let mut tar = tar::Builder::new(encoder);
            append_file(&mut tar, "payload.tar.zst", &self.payload, 0o644)?;
            append_file(&mut tar, "build.script", &self.script, 0o644)?;
            let manifest = serde_json::to_vec_pretty(&self.manifest)?;
            ensure!(manifest.len() as u64 <= MAX_MANIFEST, "manifest too large");
            append_file(&mut tar, "manifest.json", &manifest, 0o644)?;
            tar.into_inner()?.finish()?;
        }
        ensure!(
            temp.as_file().metadata()?.len() <= MAX_COMPRESSED,
            "compressed archive too large"
        );
        temp.as_file().sync_all()?;
        if replace {
            temp.persist(path).map_err(|error| error.error)?;
        } else {
            temp.persist_noclobber(path).map_err(|error| error.error)?;
        }
        Ok(())
    }

    pub fn unpack(&self, dest: &Path) -> Result<()> {
        let expanded = decompress(&self.payload, MAX_EXPANDED)?;
        let parent = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        ensure!(!dest.exists(), "destination already exists");
        let temporary = tempfile::Builder::new()
            .prefix(".anynix-unpack-")
            .tempdir_in(parent)?;
        validate_payload(&expanded, Some(temporary.path()))?;
        // The destination is created exclusively; this avoids replacing an existing directory.
        let mut options = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            options.mode(0o700);
        }
        options
            .create(dest)
            .with_context(|| format!("creating destination {}", dest.display()))?;
        for entry in fs::read_dir(temporary.path())? {
            let entry = entry?;
            fs::rename(entry.path(), dest.join(entry.file_name()))?;
        }
        Ok(())
    }
}

fn validate_payload(expanded: &[u8], dest: Option<&Path>) -> Result<()> {
    let mut archive = tar::Archive::new(Cursor::new(expanded));
    let mut seen = std::collections::BTreeSet::<PathBuf>::new();
    let mut files = std::collections::BTreeSet::<PathBuf>::new();
    let mut directories = std::collections::BTreeSet::<PathBuf>::new();
    for item in archive.entries()? {
        let mut entry = item?;
        let path = entry.path()?.into_owned();
        ensure!(
            !path.as_os_str().is_empty()
                && path.components().all(|c| matches!(c, Component::Normal(_))),
            "unsafe payload path: {}",
            path.display()
        );
        ensure!(
            seen.insert(path.clone()),
            "duplicate payload path: {}",
            path.display()
        );
        let kind = entry.header().entry_type();
        ensure!(
            kind.is_file() || kind.is_dir(),
            "links and special files are not allowed in payload"
        );
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            ensure!(!files.contains(parent), "file used as a parent directory");
            directories.insert(parent.to_path_buf());
        }
        if kind.is_file() {
            ensure!(!directories.contains(&path), "directory used as a file");
            files.insert(path.clone());
        } else {
            ensure!(entry.size() == 0, "directory entry has content");
            directories.insert(path.clone());
        }
        if let Some(root) = dest {
            let target = root.join(&path);
            if kind.is_dir() {
                fs::create_dir_all(&target)?;
            } else {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(entry.header().mode()? & 0o777);
                }
                let mut file = options.open(&target)?;
                std::io::copy(&mut entry, &mut file)?;
            }
        } else {
            std::io::copy(&mut entry, &mut std::io::sink())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_rejects_links_and_path_conflicts() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("target").unwrap();
        header.set_mode(0o777);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "link", std::io::empty())
            .unwrap();
        assert!(validate_payload(&builder.into_inner().unwrap(), None).is_err());

        let mut builder = tar::Builder::new(Vec::new());
        append_file(&mut builder, "file", b"one", 0o644).unwrap();
        append_file(&mut builder, "file/child", b"two", 0o644).unwrap();
        assert!(validate_payload(&builder.into_inner().unwrap(), None).is_err());
    }

    #[test]
    fn payload_rejects_duplicate_entries() {
        let mut builder = tar::Builder::new(Vec::new());
        append_file(&mut builder, "file", b"one", 0o644).unwrap();
        append_file(&mut builder, "file", b"two", 0o644).unwrap();
        assert!(validate_payload(&builder.into_inner().unwrap(), None).is_err());
    }
}
