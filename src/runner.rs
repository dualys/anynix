use std::{
    ffi::OsStr,
    fs,
    path::{Component, Path},
    process::Command,
};

use anyhow::{Context, Result, ensure};

pub fn run(prefix: &Path, program: &OsStr, args: &[std::ffi::OsString]) -> Result<()> {
    let path = Path::new(program);
    let mut components = path.components();
    ensure!(
        matches!((components.next(), components.next()), (Some(Component::Normal(name)), None) if name == program),
        "program must be a single executable name, not a path"
    );
    let prefix = fs::canonicalize(prefix)
        .with_context(|| format!("opening application prefix {}", prefix.display()))?;
    let bin = prefix.join("bin");
    let metadata =
        fs::symlink_metadata(&bin).with_context(|| format!("opening {}", bin.display()))?;
    ensure!(
        metadata.is_dir(),
        "{} must be a directory, not a link",
        bin.display()
    );
    let executable = bin.join(program);
    let metadata = fs::symlink_metadata(&executable)
        .with_context(|| format!("opening executable {}", executable.display()))?;
    ensure!(
        metadata.is_file(),
        "{} must be a regular file, not a link",
        executable.display()
    );
    let mut command = Command::new(&executable);
    command.args(args);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        Err(error).with_context(|| format!("executing {}", executable.display()))
    }

    #[cfg(not(unix))]
    {
        let status = command
            .status()
            .with_context(|| format!("executing {}", executable.display()))?;
        if let Some(code) = status.code() {
            std::process::exit(code);
        }
        anyhow::bail!("program terminated without an exit code");
    }
}
