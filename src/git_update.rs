use crate::{archive, crypto};
use anyhow::{Context, Result, bail, ensure};
use std::{
    io::Read,
    path::Path,
    process::{Command, Stdio},
};

const MAX_TREE: u64 = 512 * 1024 * 1024;

fn git(args: &[&str], directory: Option<&Path>) -> Result<String> {
    let mut command = Command::new("git");
    command
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1");
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    let output = command.output().context("running git")?;
    ensure!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

pub fn update(
    old: &Path,
    repository: Option<&str>,
    branch: Option<&str>,
    key: &Path,
    output: &Path,
) -> Result<String> {
    let package = archive::Package::read(old)?;
    let trust = crypto::trust_dir()?;
    package.verify(&trust)?;
    let signing_key = crypto::load_key(key)?;
    crypto::ensure_trusted_signer(crypto::Role::Developer, &signing_key, &trust)?;
    ensure!(
        package.manifest.attestations[0].public_key
            == crypto::hex(signing_key.verifying_key().as_bytes()),
        "the update must be signed by the original developer"
    );
    let default_repository;
    let repository = match repository {
        Some(repository) => repository,
        None => {
            default_repository = git(&["remote", "get-url", "origin"], None)
                .context("provide --repository or configure a Git origin")?;
            &default_repository
        }
    };
    ensure!(
        !repository.is_empty()
            && !repository.starts_with('-')
            && !repository.contains("::")
            && (!repository.contains("://")
                || repository.starts_with("https://")
                || repository.starts_with("ssh://")
                || repository.starts_with("file://")),
        "invalid Git repository"
    );
    if let Some(branch) = branch {
        ensure!(
            !branch.is_empty() && !branch.starts_with('-'),
            "invalid Git branch"
        );
    }
    let temporary = tempfile::tempdir()?;
    let clone = temporary.path().join("repository");
    let clone_path = clone.to_str().context("temporary path is not UTF-8")?;
    let mut args = vec![
        "-c",
        "core.hooksPath=/dev/null",
        "clone",
        "--quiet",
        "--no-checkout",
        "--no-local",
    ];
    if let Some(branch) = branch {
        args.extend(["--branch", branch, "--single-branch"]);
    }
    args.extend(["--", repository, clone_path]);
    git(&args, None).context("cloning the remote repository")?;
    let commit = git(&["rev-parse", "--verify", "HEAD^{commit}"], Some(&clone))?;
    let tree = git(&["rev-parse", "--verify", "HEAD^{tree}"], Some(&clone))?;
    let modes = git(
        &["ls-tree", "-r", "--format=%(objectmode)", &tree],
        Some(&clone),
    )?;
    ensure!(
        !modes.lines().any(|mode| mode == "160000"),
        "remote Git tree contains submodules, which are not supported"
    );
    std::fs::write(
        clone.join(".git/info/attributes"),
        b"* -export-ignore -export-subst\n",
    )
    .context("disabling Git archive export attributes")?;
    let mut child = Command::new("git")
        .args(["archive", "--format=tar", &tree])
        .current_dir(&clone)
        .stdout(Stdio::piped())
        .spawn()
        .context("archiving remote tree")?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .context("missing Git archive output")?
        .take(MAX_TREE + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > MAX_TREE {
        child.kill().context("stopping oversized Git archive")?;
        child.wait()?;
        read.context("reading Git archive")?;
        bail!("remote Git tree exceeds the size limit");
    }
    ensure!(child.wait()?.success(), "git archive failed");
    let source = temporary.path().join("source");
    std::fs::create_dir(&source)?;
    archive::validate_payload(&bytes, Some(&source)).context("invalid remote Git tree")?;
    archive::pack(&source, None, key, output)?;
    Ok(commit)
}
