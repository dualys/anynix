use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use std::{io::Write, path::Path};
use url::Url;

const MAX_ARCHIVE: usize = 256 * 1024 * 1024;

pub fn token() -> Result<String> {
    let token = std::env::var("ANYNIX_REVIEW_TOKEN")
        .context("ANYNIX_REVIEW_TOKEN is required for the private review service")?;
    ensure!(
        token.len() >= 32,
        "review token must contain at least 32 characters"
    );
    ensure!(!token.contains(['\r', '\n']), "invalid review token");
    Ok(token)
}

fn client(server: &str) -> Result<(reqwest::Client, Url)> {
    let url = Url::parse(server).context("invalid review service URL")?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "review service URL must not contain credentials, a path, query or fragment"
    );
    let local = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && local),
        "review service requires HTTPS except on loopback"
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?;
    Ok((client, url))
}

async fn checked(mut response: reqwest::Response) -> Result<reqwest::Response> {
    let status = response.status();
    if !status.is_success() {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len() + chunk.len() <= 8192,
                "review service returned HTTP {status} with an oversized error"
            );
            body.extend_from_slice(&chunk);
        }
        let message = String::from_utf8_lossy(&body);
        anyhow::bail!("review service returned HTTP {status}: {}", message.trim());
    }
    Ok(response)
}

fn read_archive(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_ARCHIVE as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_ARCHIVE, "archive too large");
    Ok(bytes)
}

pub async fn submit(server: &str, path: &Path, parent: Option<i64>) -> Result<()> {
    let (client, base) = client(server)?;
    let mut url = base.join("/v1/submissions")?;
    if let Some(parent) = parent {
        ensure!(parent > 0, "invalid submission ID");
        url.query_pairs_mut()
            .append_pair("correction_of", &parent.to_string());
    }
    let bytes = read_archive(path)?;
    let response = checked(
        client
            .post(url)
            .bearer_auth(token()?)
            .body(bytes)
            .send()
            .await?,
    )
    .await?;
    println!("{}", response.text().await?);
    Ok(())
}

pub async fn list(server: &str) -> Result<()> {
    let (client, base) = client(server)?;
    let response = checked(
        client
            .get(base.join("/v1/submissions")?)
            .bearer_auth(token()?)
            .send()
            .await?,
    )
    .await?;
    println!("{}", response.text().await?);
    Ok(())
}

pub async fn get(
    server: &str,
    id: i64,
    original: bool,
    reviewer: bool,
    output: &Path,
) -> Result<()> {
    ensure!(id > 0, "invalid submission ID");
    let (client, base) = client(server)?;
    let part = if original {
        "original"
    } else if reviewer {
        "reviewer"
    } else {
        "archive"
    };
    let response = checked(
        client
            .get(base.join(&format!("/v1/submissions/{id}/{part}"))?)
            .bearer_auth(token()?)
            .send()
            .await?,
    )
    .await?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    let mut stream = response.bytes_stream();
    let mut size = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        size = size.checked_add(chunk.len()).context("archive too large")?;
        ensure!(size <= MAX_ARCHIVE, "archive too large");
        file.write_all(&chunk)?;
    }
    file.as_file().sync_all()?;
    file.persist_noclobber(output)
        .map_err(|error| error.error)?;
    println!("Saved {}", output.display());
    Ok(())
}

pub async fn send(server: &str, id: i64, path: &Path, manager: bool) -> Result<()> {
    ensure!(id > 0, "invalid submission ID");
    let (client, base) = client(server)?;
    let bytes = read_archive(path)?;
    let action = if manager { "manager" } else { "decision" };
    let response = checked(
        client
            .post(base.join(&format!("/v1/submissions/{id}/{action}"))?)
            .bearer_auth(token()?)
            .body(bytes)
            .send()
            .await?,
    )
    .await?;
    println!("{}", response.text().await?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_insecure_remote_or_credentialed_urls() {
        assert!(client("http://example.com").is_err());
        assert!(client("http://localhost:3456").is_err());
        assert!(client("https://user:password@example.com").is_err());
        assert!(client("http://127.0.0.1:3456").is_ok());
        assert!(client("https://example.com").is_ok());
    }
}
