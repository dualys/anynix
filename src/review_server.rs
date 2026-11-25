use crate::{
    archive::Package,
    crypto::{self, Decision, Role},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as RoutePath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const MAX_ARCHIVE: usize = 256 * 1024 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    id: String,
    role: Role,
    token_hash: String,
    public_key: Option<PathBuf>,
    #[serde(skip)]
    public_pem: Option<Vec<u8>>,
    #[serde(skip)]
    token_digest: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    accounts: Vec<Account>,
}

struct App {
    accounts: Vec<Account>,
    database: Mutex<Connection>,
}

#[derive(Debug)]
struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    eprintln!("private review service error: {error}");
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal service error")
}

fn bad_request(error: impl std::fmt::Display) -> ApiError {
    eprintln!("private review validation error: {error}");
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, "invalid signed archive")
}

fn authenticate<'a>(
    app: &'a App,
    headers: &HeaderMap,
) -> std::result::Result<&'a Account, ApiError> {
    let value = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| value.len() >= 32)
        .ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "authentication required",
        ))?;
    let digest = blake3::hash(value.as_bytes());
    app.accounts
        .iter()
        .find(|account| blake3::Hash::from(account.token_digest) == digest)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "invalid credentials"))
}

fn private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file(),
        "{} must be a regular file",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == rustix::process::getuid().as_raw(),
            "{} has the wrong owner",
            path.display()
        );
        ensure!(
            metadata.mode() & 0o077 == 0,
            "{} must be private",
            path.display()
        );
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(metadata.is_dir(), "{} must be a directory", path.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == rustix::process::getuid().as_raw(),
            "{} has the wrong owner",
            path.display()
        );
        ensure!(
            metadata.mode() & 0o077 == 0,
            "{} must be private",
            path.display()
        );
    }
    Ok(())
}

fn load(config: &Path, database: &Path) -> Result<Arc<App>> {
    private_file(config)?;
    let bytes = fs::read(config)?;
    ensure!(bytes.len() <= 1024 * 1024, "review configuration too large");
    let mut config: Config = serde_json::from_slice(&bytes)?;
    ensure!(!config.accounts.is_empty(), "review accounts are required");
    let mut ids = HashSet::new();
    let mut tokens = HashSet::new();
    let mut signing_keys = HashSet::new();
    for account in &mut config.accounts {
        ensure!(
            !account.id.is_empty()
                && account.id.len() <= 128
                && account
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid account id"
        );
        ensure!(ids.insert(account.id.clone()), "duplicate account id");
        account.token_digest =
            crypto::decode_hex::<32>(&account.token_hash).context("invalid token hash")?;
        ensure!(
            tokens.insert(account.token_digest),
            "duplicate account token"
        );
        ensure!(
            matches!(
                account.role,
                Role::Developer | Role::Reviewer | Role::Manager
            ),
            "invalid account role"
        );
        let key = account
            .public_key
            .as_ref()
            .context("signer public key is required")?;
        ensure!(fs::metadata(key)?.is_file(), "public key must be a file");
        let pem = fs::read(key).context("reading account public key")?;
        let key = VerifyingKey::from_public_key_pem(std::str::from_utf8(&pem)?)
            .context("invalid account public key")?;
        ensure!(
            signing_keys.insert(*key.as_bytes()),
            "account signing keys must be distinct"
        );
        account.public_pem = Some(pem);
    }
    let parent = database
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    private_directory(parent)?;
    if !database.exists() {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(database)?;
    }
    private_file(database)?;
    let connection = Connection::open(database)?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         CREATE TABLE IF NOT EXISTS submissions (
           id INTEGER PRIMARY KEY,
           owner TEXT NOT NULL,
           developer_key BLOB NOT NULL,
           correction_of INTEGER REFERENCES submissions(id),
           original BLOB NOT NULL,
           decision BLOB,
           manager_decision BLOB,
           status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'manager_approved')),
           reviewer TEXT,
           reviewer_key BLOB,
           manager TEXT,
           reason TEXT,
           created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
         );",
    )?;
    Ok(Arc::new(App {
        accounts: config.accounts,
        database: Mutex::new(connection),
    }))
}

fn verify(
    bytes: &[u8],
    developer_key: &[u8],
    reviewer_key: Option<&[u8]>,
    manager_key: Option<&[u8]>,
) -> Result<Package> {
    let temporary = tempfile::tempdir()?;
    fs::write(temporary.path().join("developer.pem"), developer_key)?;
    if let Some(key) = reviewer_key {
        fs::write(temporary.path().join("reviewer.pem"), key)?;
    }
    if let Some(key) = manager_key {
        fs::write(temporary.path().join("manager.pem"), key)?;
    }
    let mut input = tempfile::NamedTempFile::new()?;
    input.write_all(bytes)?;
    let package = Package::read(input.path())?;
    package.verify(temporary.path())?;
    Ok(package)
}

#[derive(Deserialize)]
struct SubmitQuery {
    correction_of: Option<i64>,
}

async fn submit(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Query(query): Query<SubmitQuery>,
    body: Bytes,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let account = authenticate(&app, &headers)?;
    if account.role != Role::Developer {
        return Err(ApiError(StatusCode::FORBIDDEN, "developer role required"));
    }
    let key = account
        .public_pem
        .as_deref()
        .expect("validated account key");
    let package = verify(&body, key, None, None).map_err(bad_request)?;
    package.ensure_stage(Role::Developer).map_err(bad_request)?;
    package.validate_for_review().map_err(bad_request)?;
    let db = app.database.lock().map_err(internal)?;
    if let Some(parent) = query.correction_of {
        let previous: Option<(String, String)> = db
            .query_row(
                "SELECT owner, status FROM submissions WHERE id = ?1",
                [parent],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(internal)?;
        if previous != Some((account.id.clone(), "rejected".to_string())) {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "correction requires your rejected submission",
            ));
        }
    }
    db.execute(
        "INSERT INTO submissions (owner, developer_key, correction_of, original, status) VALUES (?1, ?2, ?3, ?4, 'pending')",
        params![account.id, key, query.correction_of, body.as_ref()],
    ).map_err(internal)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"id": db.last_insert_rowid(), "status": "pending"})),
    ))
}

#[derive(Serialize)]
struct Submission {
    id: i64,
    owner: String,
    correction_of: Option<i64>,
    status: String,
    reviewer: Option<String>,
    manager: Option<String>,
    reason: Option<String>,
    created_at: String,
}

async fn list(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> std::result::Result<impl IntoResponse, ApiError> {
    authenticate(&app, &headers)?;
    let db = app.database.lock().map_err(internal)?;
    let mut statement = db
        .prepare(
            "SELECT id, owner, correction_of, status, reviewer, manager, reason, created_at FROM submissions ORDER BY id",
        )
        .map_err(internal)?;
    let rows = statement
        .query_map([], |row| {
            Ok(Submission {
                id: row.get(0)?,
                owner: row.get(1)?,
                correction_of: row.get(2)?,
                status: row.get(3)?,
                reviewer: row.get(4)?,
                manager: row.get(5)?,
                reason: row.get(6)?,
                created_at: row.get(7)?,
            })
        })
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok(Json(rows))
}

async fn get_archive(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    RoutePath((id, kind)): RoutePath<(i64, String)>,
) -> std::result::Result<impl IntoResponse, ApiError> {
    authenticate(&app, &headers)?;
    if kind != "archive" && kind != "original" && kind != "reviewer" {
        return Err(ApiError(StatusCode::NOT_FOUND, "not found"));
    }
    let db = app.database.lock().map_err(internal)?;
    let row: Option<Option<Vec<u8>>> = db
        .query_row(
            "SELECT CASE WHEN ?2 = 'original' THEN original WHEN ?2 = 'reviewer' THEN decision ELSE COALESCE(manager_decision, decision, original) END FROM submissions WHERE id = ?1",
            params![id, kind],
            |row| row.get(0),
        )
        .optional()
        .map_err(internal)?;
    let archive = row
        .flatten()
        .ok_or(ApiError(StatusCode::NOT_FOUND, "not found"))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        archive,
    ))
}

async fn decide(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<i64>,
    body: Bytes,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let account = authenticate(&app, &headers)?;
    if account.role != Role::Reviewer {
        return Err(ApiError(StatusCode::FORBIDDEN, "reviewer role required"));
    }
    let db = app.database.lock().map_err(internal)?;
    let row: Option<(Vec<u8>, Vec<u8>, String)> = db
        .query_row(
            "SELECT original, developer_key, status FROM submissions WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(internal)?;
    let (original, developer_key, status) =
        row.ok_or(ApiError(StatusCode::NOT_FOUND, "not found"))?;
    if status != "pending" {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "submission has already been reviewed",
        ));
    }
    let previous = verify(&original, &developer_key, None, None).map_err(internal)?;
    let reviewed =
        verify(&body, &developer_key, account.public_pem.as_deref(), None).map_err(bad_request)?;
    if reviewed.manifest.attestations.len() != 2
        || reviewed.manifest.attestations[1].role != Role::Reviewer
        || reviewed.manifest.payload_hash != previous.manifest.payload_hash
        || reviewed.manifest.script_hash != previous.manifest.script_hash
        || serde_json::to_vec(&reviewed.manifest.attestations[0]).map_err(internal)?
            != serde_json::to_vec(&previous.manifest.attestations[0]).map_err(internal)?
    {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "decision does not match submission",
        ));
    }
    let entry = &reviewed.manifest.attestations[1];
    let status = match entry.decision {
        Decision::Approve => "approved",
        Decision::Reject => "rejected",
    };
    let changed = db.execute(
        "UPDATE submissions SET decision = ?1, status = ?2, reviewer = ?3, reason = ?4, reviewer_key = ?5 WHERE id = ?6 AND status = 'pending'",
        params![body.as_ref(), status, account.id, entry.reason, account.public_pem, id],
    ).map_err(internal)?;
    if changed != 1 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "submission has already been reviewed",
        ));
    }
    Ok(Json(serde_json::json!({"id": id, "status": status})))
}

async fn manager_approve(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    RoutePath(id): RoutePath<i64>,
    body: Bytes,
) -> std::result::Result<impl IntoResponse, ApiError> {
    let account = authenticate(&app, &headers)?;
    if account.role != Role::Manager {
        return Err(ApiError(StatusCode::FORBIDDEN, "manager role required"));
    }
    let db = app.database.lock().map_err(internal)?;
    type ReviewRow = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, String);
    let row: Option<ReviewRow> = db
        .query_row(
            "SELECT developer_key, reviewer_key, decision, status FROM submissions WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(internal)?;
    let (developer_key, reviewer_key, reviewed, status) =
        row.ok_or(ApiError(StatusCode::NOT_FOUND, "not found"))?;
    if status != "approved" {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "submission is not approved by a reviewer",
        ));
    }
    let reviewer_key = reviewer_key.ok_or_else(|| internal("missing reviewer key"))?;
    let reviewed = reviewed.ok_or_else(|| internal("missing reviewer decision"))?;
    let previous =
        verify(&reviewed, &developer_key, Some(&reviewer_key), None).map_err(internal)?;
    let approved = verify(
        &body,
        &developer_key,
        Some(&reviewer_key),
        account.public_pem.as_deref(),
    )
    .map_err(bad_request)?;
    approved.ensure_stage(Role::Manager).map_err(bad_request)?;
    if approved.manifest.attestations.len() != 3
        || approved.manifest.payload_hash != previous.manifest.payload_hash
        || approved.manifest.script_hash != previous.manifest.script_hash
        || serde_json::to_vec(&approved.manifest.attestations[..2]).map_err(internal)?
            != serde_json::to_vec(&previous.manifest.attestations).map_err(internal)?
    {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            "approval does not match review",
        ));
    }
    let changed = db.execute(
        "UPDATE submissions SET manager_decision = ?1, manager = ?2, status = 'manager_approved' WHERE id = ?3 AND status = 'approved'",
        params![body.as_ref(), account.id, id],
    ).map_err(internal)?;
    if changed != 1 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "submission has already been processed",
        ));
    }
    Ok(Json(
        serde_json::json!({"id": id, "status": "manager_approved"}),
    ))
}

pub async fn serve(config: &Path, database: &Path, listen: SocketAddr) -> Result<()> {
    ensure!(
        listen.ip().is_loopback(),
        "review service must listen on loopback; use an HTTPS proxy or SSH tunnel"
    );
    let app = load(config, database)?;
    let router = Router::new()
        .route("/v1/submissions", get(list).post(submit))
        .route("/v1/submissions/{id}/{kind}", get(get_archive))
        .route("/v1/submissions/{id}/decision", post(decide))
        .route("/v1/submissions/{id}/manager", post(manager_approve))
        .layer(DefaultBodyLimit::max(MAX_ARCHIVE))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!(
        "Private review service listening on {}",
        listener.local_addr()?
    );
    axum::serve(listener, router).await?;
    Ok(())
}
