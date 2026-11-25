use crate::crypto::Role;
use clap::{Parser, Subcommand};
use std::{ffi::OsString, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "anynix",
    version,
    about = "Create and verify signed Unix package archives"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate an Ed25519 key pair for a signing role
    Keygen {
        /// Role associated with this key pair
        #[arg(long, value_enum)]
        role: Role,
        /// Private key path; the public key is written to <path>.pub.pem
        #[arg(long)]
        out: PathBuf,
    },
    /// Package files selected by anynix.yaml and sign them as Developer
    Pack {
        /// Source directory to freeze into the archive (default: current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
        /// UTF-8 build script (overrides build_script in anynix.yaml)
        #[arg(long)]
        script: Option<PathBuf>,
        /// Developer's Ed25519 private key (default: ~/.config/anynix/keys/developer.pem)
        #[arg(long)]
        key: Option<PathBuf>,
        /// Destination archive (default: package.anynix); must not already exist
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
    /// Create a new Developer-signed archive from a remote Git repository
    Update {
        /// Previous signed archive; it is never modified
        archive: PathBuf,
        /// Git repository URL or local path (default: origin of the current repository)
        #[arg(long)]
        repository: Option<String>,
        /// Remote branch to use (default: the remote's default branch)
        #[arg(long)]
        branch: Option<String>,
        /// Developer's Ed25519 private key
        #[arg(long)]
        key: Option<PathBuf>,
        /// New archive; must not already exist
        #[arg(short = 'o', long)]
        output: PathBuf,
    },
    /// Compare a verified archive's selected sources with a local source tree
    Diff {
        /// Signed source archive to compare
        archive: PathBuf,
        /// Local source directory containing anynix.yaml
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Show archive hashes and verify the attestation chain against trusted keys
    Ls {
        /// Archive to inspect
        archive: PathBuf,
    },
    /// Verify the archive and extract its source payload into a new directory
    Unpack {
        /// Archive to verify and extract
        archive: PathBuf,
        /// New destination directory
        #[arg(short = 'o', long)]
        dest: PathBuf,
    },
    /// Install a verified release and its dependencies from a local TUF repository
    Install {
        /// Package name, optionally followed by @ and an exact version
        package: String,
        /// Local repository containing metadata/, targets/ and blobs/
        #[arg(long)]
        repository: PathBuf,
        /// TUF root authenticated independently of the repository
        #[arg(long)]
        trust_root: PathBuf,
        /// Existing private directory for persistent TUF state
        #[arg(long)]
        state: PathBuf,
        /// Application prefix (default: /apps)
        #[arg(long, default_value = "/apps")]
        prefix: PathBuf,
    },
    /// Run a local executable from the application prefix without changing PATH
    Run {
        /// Application prefix containing bin/ (default: /apps)
        #[arg(long, default_value = "/apps")]
        prefix: PathBuf,
        /// Executable name, not a path
        program: OsString,
        /// Arguments passed unchanged to the executable
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Verify a submission and optionally send it to the private review service
    Submit {
        /// Developer-signed archive
        archive: PathBuf,
        /// Private review service URL; omit for local verification only
        #[arg(long)]
        server: Option<String>,
        /// ID of a rejected submission being corrected
        #[arg(long)]
        correction_of: Option<i64>,
    },
    /// Run or use the private review service
    Review {
        #[command(subcommand)]
        command: ReviewCommand,
    },
    /// Validate the payload structure and add a Reviewer signature
    Audit {
        /// Developer-signed archive to review
        archive: PathBuf,
        /// Reviewer's trusted Ed25519 private key
        #[arg(long)]
        key: PathBuf,
    },
    /// Sign a Reviewer rejection and its reason
    Reject {
        /// Developer-signed archive to reject
        archive: PathBuf,
        /// Explanation to send back to the developer
        #[arg(long)]
        reason: String,
        /// Reviewer's trusted Ed25519 private key
        #[arg(long)]
        key: PathBuf,
    },
    /// Sign as Manager; Proxmox build orchestration is not implemented
    Approve {
        /// Archive approved by a Reviewer
        archive: PathBuf,
        /// Manager's trusted Ed25519 private key
        #[arg(long)]
        key: PathBuf,
        /// Record the Manager signature without attempting a build
        #[arg(long)]
        review_only: bool,
        /// Requested number of CPUs
        #[arg(long, default_value_t = 1)]
        cpu: u8,
        /// Requested number of threads
        #[arg(long, default_value_t = 1)]
        thread: u8,
        /// Requested memory, e.g. 4G
        #[arg(long, default_value = "1G")]
        memory: String,
    },
    /// Connect to a build VM (not implemented)
    Ssh {
        /// Name of the ephemeral build VM
        temp_name: String,
    },
}

#[derive(Subcommand)]
pub enum ReviewCommand {
    /// Run the private review service on a loopback address
    Serve {
        /// Private JSON account configuration
        #[arg(long)]
        config: PathBuf,
        /// SQLite database in an existing private directory
        #[arg(long)]
        database: PathBuf,
        /// Loopback listen address
        #[arg(long, default_value = "127.0.0.1:3456")]
        listen: std::net::SocketAddr,
    },
    /// Print the hash of ANYNIX_REVIEW_TOKEN for the service configuration
    TokenHash,
    /// List submissions visible to the authenticated user
    List {
        /// Private review service URL
        #[arg(long)]
        server: String,
    },
    /// Download a submission or its signed review decision
    Get {
        /// Submission identifier
        id: i64,
        /// Private review service URL
        #[arg(long)]
        server: String,
        /// Download the original Developer-signed archive
        #[arg(long, conflicts_with = "reviewer")]
        original: bool,
        /// Download the signed Reviewer decision, even after Manager approval
        #[arg(long)]
        reviewer: bool,
        /// Destination; must not already exist
        #[arg(short = 'o', long)]
        output: PathBuf,
    },
    /// Send a locally signed Reviewer or Manager decision to the private service
    Send {
        /// Submission identifier
        id: i64,
        /// Archive signed by the Reviewer or Manager
        archive: PathBuf,
        /// Private review service URL
        #[arg(long)]
        server: String,
    },
}
