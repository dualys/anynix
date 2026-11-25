use std::{collections::BTreeMap, fs, io::Read, path::Path, process::Command};

fn members(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let input = fs::read(path).unwrap();
    let decoded = zstd::decode_all(input.as_slice()).unwrap();
    let mut archive = tar::Archive::new(decoded.as_slice());
    archive
        .entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_str().unwrap().to_owned();
            let mut content = Vec::new();
            entry.read_to_end(&mut content).unwrap();
            (name, content)
        })
        .collect()
}

fn write_members(path: &Path, entries: &BTreeMap<String, Vec<u8>>) {
    let encoder = zstd::Encoder::new(Vec::new(), 3).unwrap();
    let mut archive = tar::Builder::new(encoder);
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, name, bytes.as_slice())
            .unwrap();
    }
    let bytes = archive.into_inner().unwrap().finish().unwrap();
    fs::write(path, bytes).unwrap();
}

fn run(root: &Path, args: &[&str], success: bool) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_anynix"))
        .current_dir(root)
        .env("HOME", root)
        .env("ANYNIX_TRUST_DIR", root.join("trust"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(
        output.status.success(),
        success,
        "command {args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn pack_defaults_and_explicit_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let key_dir = root.join(".config/anynix/keys");
    fs::create_dir_all(&key_dir).unwrap();
    let key = key_dir.join("developer.pem");
    run(
        root,
        &[
            "keygen",
            "--role",
            "developer",
            "--out",
            key.to_str().unwrap(),
        ],
        true,
    );
    fs::write(
        root.join("anynix.yaml"),
        "build_script: build.script\ninclude:\n  - file\n",
    )
    .unwrap();
    fs::write(root.join("build.script"), b"default script\n").unwrap();
    fs::write(root.join("file"), b"source").unwrap();
    run(root, &["pack"], true);
    assert_eq!(
        members(&root.join("package.anynix"))["build.script"],
        b"default script\n"
    );
    run(root, &["pack"], false);
    fs::write(root.join("alternate.script"), b"override script\n").unwrap();
    run(
        root,
        &[
            "pack",
            ".",
            "--script",
            "alternate.script",
            "--key",
            key.to_str().unwrap(),
            "-o",
            "override.anynix",
        ],
        true,
    );
    assert_eq!(
        members(&root.join("override.anynix"))["build.script"],
        b"override script\n"
    );

    fs::create_dir(root.join("project")).unwrap();
    fs::write(
        root.join("project/anynix.yaml"),
        "build_script: build.script\ninclude:\n  - file\n",
    )
    .unwrap();
    fs::write(root.join("project/build.script"), b"project script\n").unwrap();
    fs::write(root.join("project/file"), b"nested source").unwrap();
    run(root, &["pack", "project", "-o", "nested.anynix"], true);
    assert_eq!(
        members(&root.join("nested.anynix"))["build.script"],
        b"project script\n"
    );
}

#[test]
fn pack_refuses_private_key_in_payload_or_script() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("build.script"), b"true\n").unwrap();
    run(
        root,
        &["keygen", "--role", "developer", "--out", "private.key"],
        true,
    );
    fs::write(
        root.join("anynix.yaml"),
        "build_script: build.script\ninclude:\n  - private.key\n",
    )
    .unwrap();
    let result = run(root, &["pack", "--key", "private.key"], false);
    assert!(result.contains("refusing to include the private signing key"));
    assert!(!root.join("package.anynix").exists());
    fs::write(
        root.join("anynix.yaml"),
        "build_script: private.key\ninclude:\n  - build.script\n",
    )
    .unwrap();
    let result = run(root, &["pack", "--key", "private.key"], false);
    assert!(result.contains("build script must not be the private signing key"));
    assert!(!root.join("package.anynix").exists());
}

#[test]
fn help_describes_commands_and_their_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let help = run(dir.path(), &["--help"], true);
    assert!(help.contains("Package files selected by anynix.yaml and sign them as Developer"));
    assert!(help.contains("network transfer is not implemented"));
    let pack_help = run(dir.path(), &["pack", "--help"], true);
    assert!(pack_help.contains("Source directory to freeze into the archive"));
    assert!(pack_help.contains("Developer's Ed25519 private key"));
    let approve_help = run(dir.path(), &["approve", "--help"], true);
    assert!(approve_help.contains("Requested memory"));
}

#[test]
fn pack_uses_yaml_selection_and_ignore_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir(root.join("trust")).unwrap();
    fs::create_dir_all(root.join("source/src")).unwrap();
    fs::write(root.join("build.script"), b"true\n").unwrap();
    run(
        root,
        &["keygen", "--role", "developer", "--out", "developer"],
        true,
    );
    fs::copy(
        root.join("developer.pub.pem"),
        root.join("trust/developer.pem"),
    )
    .unwrap();
    let pack_args = [
        "pack",
        "source",
        "--script",
        "build.script",
        "--key",
        "developer",
        "-o",
        "package.anynix",
    ];
    run(root, &pack_args, false);
    assert!(!root.join("package.anynix").exists());
    fs::write(
        root.join("source/anynix.yaml"),
        "include:\n  - 'src/**'\n  - README.md\n",
    )
    .unwrap();
    fs::write(root.join("source/.ignore"), "src/skip-ignore\n").unwrap();
    fs::write(root.join("source/.gitignore"), "src/skip-git\n").unwrap();
    fs::write(root.join("source/src/ok"), b"selected").unwrap();
    fs::write(root.join("source/src/skip-ignore"), b"ignored").unwrap();
    fs::write(root.join("source/src/skip-git"), b"ignored").unwrap();
    fs::write(root.join("source/README.md"), b"readme").unwrap();
    fs::write(root.join("source/secret"), b"not selected").unwrap();
    run(root, &pack_args, true);
    run(root, &["unpack", "package.anynix", "-o", "out"], true);
    assert_eq!(fs::read(root.join("out/src/ok")).unwrap(), b"selected");
    assert_eq!(fs::read(root.join("out/README.md")).unwrap(), b"readme");
    assert!(!root.join("out/src/skip-ignore").exists());
    assert!(!root.join("out/src/skip-git").exists());
    assert!(!root.join("out/secret").exists());
}

#[test]
fn approved_and_rejected_workflows() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir(root.join("trust")).unwrap();
    fs::create_dir(root.join("source")).unwrap();
    fs::write(root.join("source/file"), b"frozen source").unwrap();
    fs::write(root.join("source/anynix.yaml"), "include:\n  - file\n").unwrap();
    fs::write(root.join("build.script"), b"cp file %bin%/file\n").unwrap();
    for role in ["developer", "reviewer", "manager"] {
        run(root, &["keygen", "--role", role, "--out", role], true);
        fs::copy(
            root.join(format!("{role}.pub.pem")),
            root.join(format!("trust/{role}.pem")),
        )
        .unwrap();
    }

    run(
        root,
        &[
            "pack",
            "source",
            "--script",
            "build.script",
            "--key",
            "developer",
            "-o",
            "package.anynix",
        ],
        true,
    );
    let original_payload = members(&root.join("package.anynix"))["payload.tar.zst"].clone();
    run(
        root,
        &[
            "pack",
            "source",
            "--script",
            "build.script",
            "--key",
            "developer",
            "-o",
            "package.anynix",
        ],
        false,
    );
    run(root, &["submit", "package.anynix"], true);
    run(
        root,
        &["audit", "package.anynix", "--key", "developer"],
        false,
    );
    run(
        root,
        &["audit", "package.anynix", "--key", "reviewer"],
        true,
    );
    assert_eq!(
        members(&root.join("package.anynix"))["payload.tar.zst"],
        original_payload
    );
    let result = run(
        root,
        &[
            "approve",
            "package.anynix",
            "--key",
            "manager",
            "--cpu",
            "4",
            "--thread",
            "4",
            "--memory",
            "4G",
        ],
        false,
    );
    assert!(result.contains("no build was started"));
    let listing = run(root, &["ls", "package.anynix"], true);
    assert!(listing.contains("Manager: valid and trusted"));
    assert!(listing.contains("3 of 5 stages"));
    run(root, &["unpack", "package.anynix", "-o", "out"], true);
    assert_eq!(fs::read(root.join("out/file")).unwrap(), b"frozen source");
    run(root, &["unpack", "package.anynix", "-o", "out"], false);

    fs::remove_file(root.join("trust/reviewer.pem")).unwrap();
    run(root, &["ls", "package.anynix"], false);
    fs::copy(
        root.join("reviewer.pub.pem"),
        root.join("trust/reviewer.pem"),
    )
    .unwrap();

    run(
        root,
        &[
            "pack",
            "source",
            "--script",
            "build.script",
            "--key",
            "developer",
            "-o",
            "rejected.anynix",
        ],
        true,
    );
    run(
        root,
        &[
            "reject",
            "rejected.anynix",
            "--reason",
            "fix test",
            "--key",
            "reviewer",
        ],
        true,
    );
    let listing = run(root, &["ls", "rejected.anynix"], true);
    assert!(listing.contains("Reason: fix test"));
    let mut altered_rejection = members(&root.join("rejected.anynix"));
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&altered_rejection["manifest.json"]).unwrap();
    manifest["attestations"][1]["reason"] = "different reason".into();
    altered_rejection.insert(
        "manifest.json".into(),
        serde_json::to_vec(&manifest).unwrap(),
    );
    write_members(&root.join("altered-rejection.anynix"), &altered_rejection);
    run(root, &["ls", "altered-rejection.anynix"], false);
    run(root, &["submit", "rejected.anynix"], false);
    run(
        root,
        &["audit", "rejected.anynix", "--key", "reviewer"],
        false,
    );
    run(
        root,
        &["unpack", "rejected.anynix", "-o", "rejected-out"],
        false,
    );
    assert!(!root.join("rejected-out").exists());
    run(root, &["ssh", "test-vm"], false);

    let mut tampered = members(&root.join("package.anynix"));
    tampered.get_mut("payload.tar.zst").unwrap()[0] ^= 1;
    write_members(&root.join("tampered.anynix"), &tampered);
    run(
        root,
        &["unpack", "tampered.anynix", "-o", "tampered-out"],
        false,
    );
    assert!(!root.join("tampered-out").exists());
}
