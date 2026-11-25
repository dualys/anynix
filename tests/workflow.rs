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
    run_with_token(root, args, None, success)
}

fn run_with_token(root: &Path, args: &[&str], token: Option<&str>, success: bool) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_anynix"));
    command
        .current_dir(root)
        .env("HOME", root)
        .env("ANYNIX_TRUST_DIR", root.join("trust"))
        .args(args);
    if let Some(token) = token {
        command.env("ANYNIX_REVIEW_TOKEN", token);
    } else {
        command.env_remove("ANYNIX_REVIEW_TOKEN");
    }
    let output = command.output().unwrap();
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

#[cfg(unix)]
#[test]
fn private_review_service_preserves_decisions_and_corrections() {
    use std::{
        net::{TcpListener, TcpStream},
        os::unix::fs::PermissionsExt,
        process::{Child, Stdio},
        time::Duration,
    };
    struct Server(Child);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir(root.join("trust")).unwrap();
    fs::create_dir(root.join("private")).unwrap();
    fs::set_permissions(root.join("private"), fs::Permissions::from_mode(0o700)).unwrap();
    let mut accounts = Vec::new();
    for (id, role, token) in [
        ("alice", "Developer", "a".repeat(64)),
        ("bob", "Developer", "b".repeat(64)),
        ("reviewer", "Reviewer", "c".repeat(64)),
        ("manager", "Manager", "d".repeat(64)),
    ] {
        run(
            root,
            &["keygen", "--role", &role.to_lowercase(), "--out", id],
            true,
        );
        let public_key = root.join(format!("{id}.pub.pem"));
        accounts.push(serde_json::json!({
            "id": id, "role": role, "token_hash": blake3::hash(token.as_bytes()).to_hex().to_string(),
            "public_key": public_key,
        }));
    }
    fs::copy(root.join("alice.pub.pem"), root.join("trust/developer.pem")).unwrap();
    fs::copy(
        root.join("reviewer.pub.pem"),
        root.join("trust/reviewer.pem"),
    )
    .unwrap();
    fs::copy(root.join("manager.pub.pem"), root.join("trust/manager.pem")).unwrap();
    fs::write(
        root.join("private/config.json"),
        serde_json::to_vec(&serde_json::json!({"accounts": accounts})).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        root.join("private/config.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    run(
        root,
        &[
            "review",
            "serve",
            "--config",
            "private/config.json",
            "--database",
            "private/review.db",
            "--listen",
            "0.0.0.0:3456",
        ],
        false,
    );
    fs::set_permissions(
        root.join("private/config.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    run(
        root,
        &[
            "review",
            "serve",
            "--config",
            "private/config.json",
            "--database",
            "private/review.db",
        ],
        false,
    );
    fs::set_permissions(
        root.join("private/config.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let address_string = address.to_string();
    let url = format!("http://{address}");
    let spawn_server = || {
        Server(
            Command::new(env!("CARGO_BIN_EXE_anynix"))
                .current_dir(root)
                .args([
                    "review",
                    "serve",
                    "--config",
                    "private/config.json",
                    "--database",
                    "private/review.db",
                    "--listen",
                    &address_string,
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    };
    let mut server = spawn_server();
    let wait = || {
        for _ in 0..100 {
            if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("review service did not start");
    };
    wait();
    let alice = "a".repeat(64);
    let bob = "b".repeat(64);
    let reviewer = "c".repeat(64);
    let manager = "d".repeat(64);
    let invalid = "x".repeat(64);
    run_with_token(
        root,
        &["review", "list", "--server", &url],
        Some(&invalid),
        false,
    );
    fs::write(
        root.join("anynix.yaml"),
        "build_script: build.script\ninclude:\n  - file\n",
    )
    .unwrap();
    fs::write(root.join("build.script"), b"true\n").unwrap();
    fs::write(root.join("file"), b"first").unwrap();
    run(
        root,
        &["pack", "--key", "alice", "-o", "first.anynix"],
        true,
    );
    let submit = ["submit", "first.anynix", "--server", &url];
    run_with_token(root, &submit, Some(&manager), false);
    assert!(run_with_token(root, &submit, Some(&alice), true).contains("\"id\":1"));
    run_with_token(
        root,
        &[
            "review",
            "get",
            "1",
            "--reviewer",
            "--server",
            &url,
            "-o",
            "missing-review.anynix",
        ],
        Some(&bob),
        false,
    );
    assert!(!root.join("missing-review.anynix").exists());
    let download = [
        "review",
        "get",
        "1",
        "--server",
        &url,
        "-o",
        "review.anynix",
    ];
    run_with_token(root, &download, Some(&bob), true);
    fs::write(root.join("file"), b"different submission").unwrap();
    run(
        root,
        &["pack", "--key", "alice", "-o", "other.anynix"],
        true,
    );
    run(
        root,
        &[
            "reject",
            "other.anynix",
            "--reason",
            "different",
            "--key",
            "reviewer",
        ],
        true,
    );
    let response = tokio::runtime::Runtime::new().unwrap().block_on(async {
        reqwest::Client::new()
            .post(format!("{url}/v1/submissions/1/decision"))
            .bearer_auth(&reviewer)
            .body(fs::read(root.join("other.anynix")).unwrap())
            .send()
            .await
            .unwrap()
    });
    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    run(
        root,
        &[
            "reject",
            "review.anynix",
            "--reason",
            "fix the source",
            "--key",
            "reviewer",
        ],
        true,
    );
    let decision = ["review", "send", "1", "review.anynix", "--server", &url];
    run_with_token(root, &decision, Some(&manager), false);
    assert!(run_with_token(root, &decision, Some(&reviewer), true).contains("rejected"));
    run_with_token(root, &decision, Some(&reviewer), false);
    let history = run_with_token(
        root,
        &["review", "list", "--server", &url],
        Some(&manager),
        true,
    );
    assert!(history.contains("fix the source"));
    assert!(history.contains("rejected"));
    fs::write(root.join("file"), b"corrected").unwrap();
    run(
        root,
        &["pack", "--key", "alice", "-o", "corrected.anynix"],
        true,
    );
    let correction = [
        "submit",
        "corrected.anynix",
        "--server",
        &url,
        "--correction-of",
        "1",
    ];
    fs::copy(root.join("bob.pub.pem"), root.join("trust/developer.pem")).unwrap();
    run(root, &["pack", "--key", "bob", "-o", "bob.anynix"], true);
    run_with_token(
        root,
        &[
            "submit",
            "bob.anynix",
            "--server",
            &url,
            "--correction-of",
            "1",
        ],
        Some(&bob),
        false,
    );
    fs::copy(root.join("alice.pub.pem"), root.join("trust/developer.pem")).unwrap();
    assert!(run_with_token(root, &correction, Some(&alice), true).contains("\"id\":2"));
    run_with_token(
        root,
        &[
            "review",
            "get",
            "2",
            "--server",
            &url,
            "-o",
            "approved.anynix",
        ],
        Some(&reviewer),
        true,
    );
    run(
        root,
        &["audit", "approved.anynix", "--key", "reviewer"],
        true,
    );
    run_with_token(
        root,
        &["review", "send", "2", "approved.anynix", "--server", &url],
        Some(&reviewer),
        true,
    );
    run_with_token(
        root,
        &[
            "review",
            "get",
            "2",
            "--server",
            &url,
            "-o",
            "manager.anynix",
        ],
        Some(&manager),
        true,
    );
    run(
        root,
        &[
            "approve",
            "manager.anynix",
            "--key",
            "manager",
            "--review-only",
        ],
        true,
    );
    let manager_decision = ["review", "send", "2", "manager.anynix", "--server", &url];
    run_with_token(root, &manager_decision, Some(&reviewer), false);
    assert!(
        run_with_token(root, &manager_decision, Some(&manager), true).contains("manager_approved")
    );
    run_with_token(root, &manager_decision, Some(&manager), false);
    server.0.kill().unwrap();
    server.0.wait().unwrap();
    std::mem::forget(server);
    let _server = spawn_server();
    wait();
    let history = run_with_token(
        root,
        &["review", "list", "--server", &url],
        Some(&bob),
        true,
    );
    assert!(history.contains("fix the source"));
    assert!(history.contains("manager_approved"));
    assert!(history.contains("\"correction_of\":1"));
    run_with_token(
        root,
        &[
            "review",
            "get",
            "1",
            "--original",
            "--server",
            &url,
            "-o",
            "original.anynix",
        ],
        Some(&manager),
        true,
    );
    assert_eq!(
        fs::read(root.join("original.anynix")).unwrap(),
        fs::read(root.join("first.anynix")).unwrap()
    );
    run_with_token(
        root,
        &["review", "get", "2", "--server", &url, "-o", "final.anynix"],
        Some(&bob),
        true,
    );
    assert!(run(root, &["ls", "final.anynix"], true).contains("Manager: valid and trusted"));
    run_with_token(
        root,
        &[
            "review",
            "get",
            "2",
            "--reviewer",
            "--server",
            &url,
            "-o",
            "saved-review.anynix",
        ],
        Some(&bob),
        true,
    );
    assert_eq!(
        fs::read(root.join("saved-review.anynix")).unwrap(),
        fs::read(root.join("approved.anynix")).unwrap()
    );
}

#[cfg(unix)]
#[test]
fn run_local_program_forwards_arguments_and_exit_status() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let bin = root.join("apps/bin");
    fs::create_dir_all(&bin).unwrap();
    let program = bin.join("example");
    fs::write(&program, b"#!/bin/sh\nprintf '<%s>\\n' \"$@\"\nexit 37\n").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_anynix"))
        .args([
            "run",
            "--prefix",
            root.join("apps").to_str().unwrap(),
            "example",
            "--flag",
            "two words",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(37));
    assert_eq!(output.stdout, b"<--flag>\n<two words>\n");
}

#[cfg(unix)]
#[test]
fn run_rejects_paths_missing_programs_and_links() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let bin = root.join("apps/bin");
    fs::create_dir_all(&bin).unwrap();
    symlink("/bin/sh", bin.join("link")).unwrap();
    for program in ["../bin/sh", "/bin/sh", "missing", "link"] {
        let output = run(root, &["run", "--prefix", "apps", program], false);
        assert!(output.contains("error:"));
    }
    fs::create_dir(root.join("other")).unwrap();
    symlink(&bin, root.join("other/bin")).unwrap();
    let output = run(root, &["run", "--prefix", "other", "link"], false);
    assert!(output.contains("must be a directory, not a link"));
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
fn update_creates_a_fresh_signed_archive_from_remote_git() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let repository = root.join("repository");
    fs::create_dir(&repository).unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .current_dir(&repository)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q", "--initial-branch=main"]);
    git(&["config", "user.name", "Test"]);
    git(&["config", "user.email", "test@example.invalid"]);
    fs::write(
        repository.join("anynix.yaml"),
        "build_script: build.script\ninclude:\n  - file\n",
    )
    .unwrap();
    fs::write(repository.join("build.script"), b"true\n").unwrap();
    fs::write(repository.join("file"), b"first").unwrap();
    fs::write(repository.join(".gitattributes"), b"file export-ignore\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-qm", "first"]);
    fs::create_dir(root.join("trust")).unwrap();
    for role in ["developer", "reviewer"] {
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
            "repository",
            "--key",
            "developer",
            "-o",
            "first.anynix",
        ],
        true,
    );
    run(
        root,
        &[
            "reject",
            "first.anynix",
            "--reason",
            "fix it",
            "--key",
            "reviewer",
        ],
        true,
    );
    assert!(run(root, &["diff", "first.anynix", "repository"], true).contains("No differences"));
    let original = fs::read(root.join("first.anynix")).unwrap();
    fs::write(repository.join("file"), b"corrected").unwrap();
    git(&["add", "file"]);
    git(&["commit", "-qm", "correction"]);
    fs::write(repository.join("file"), b"uncommitted").unwrap();
    let diff = run(root, &["diff", "first.anynix", "repository"], true);
    assert!(diff.contains("-first"));
    assert!(diff.contains("+uncommitted"));
    fs::remove_file(repository.join("file")).unwrap();
    assert!(run(root, &["diff", "first.anynix", "repository"], true).contains("-first"));
    let args = [
        "update",
        "first.anynix",
        "--repository",
        repository.to_str().unwrap(),
        "--key",
        "developer",
        "-o",
        "corrected.anynix",
    ];
    let result = run(root, &args, true);
    assert!(result.contains("Updated from commit"));
    assert_eq!(fs::read(root.join("first.anynix")).unwrap(), original);
    run(root, &["unpack", "corrected.anynix", "-o", "out"], true);
    assert_eq!(fs::read(root.join("out/file")).unwrap(), b"corrected");
    assert!(!root.join("out/.git").exists());
    run(root, &args, false);
    assert_eq!(fs::read(root.join("first.anynix")).unwrap(), original);
    run(
        root,
        &[
            "update",
            "first.anynix",
            "--repository",
            repository.to_str().unwrap(),
            "--key",
            "reviewer",
            "-o",
            "wrong.anynix",
        ],
        false,
    );
    assert!(!root.join("wrong.anynix").exists());
    let mut tampered = members(&root.join("first.anynix"));
    tampered.get_mut("payload.tar.zst").unwrap()[0] ^= 1;
    write_members(&root.join("tampered.anynix"), &tampered);
    run(root, &["diff", "tampered.anynix", "repository"], false);
    run(
        root,
        &[
            "update",
            "tampered.anynix",
            "--repository",
            repository.to_str().unwrap(),
            "--key",
            "developer",
            "-o",
            "tampered-update.anynix",
        ],
        false,
    );
    assert!(!root.join("tampered-update.anynix").exists());
    let head = Command::new("git")
        .current_dir(&repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let commit = String::from_utf8(head.stdout).unwrap();
    let entry = format!("160000,{},submodule", commit.trim());
    git(&["update-index", "--add", "--cacheinfo", &entry]);
    git(&["commit", "-qm", "add submodule"]);
    let result = run(
        root,
        &[
            "update",
            "first.anynix",
            "--repository",
            repository.to_str().unwrap(),
            "--key",
            "developer",
            "-o",
            "submodule.anynix",
        ],
        false,
    );
    assert!(result.contains("submodules"));
    assert!(!root.join("submodule.anynix").exists());
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
    assert!(help.contains("optionally send it to the private review service"));
    let pack_help = run(dir.path(), &["pack", "--help"], true);
    assert!(pack_help.contains("Source directory to freeze into the archive"));
    assert!(pack_help.contains("Developer's Ed25519 private key"));
    let approve_help = run(dir.path(), &["approve", "--help"], true);
    assert!(approve_help.contains("Requested memory"));
    let install_help = run(dir.path(), &["install", "--help"], true);
    assert!(install_help.contains("--repository"));
    assert!(install_help.contains("--trust-root"));
    assert!(install_help.contains("/apps"));
    run(dir.path(), &["install", "example"], false);
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
