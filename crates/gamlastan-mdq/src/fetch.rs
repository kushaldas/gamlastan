//! HTTP transport abstraction for fetching metadata.
//!
//! The MDQ client is generic over a [`MetadataFetcher`] so that production code
//! uses [`ReqwestFetcher`] while tests inject a deterministic mock. The trait
//! deliberately deals in raw bytes — parsing, verification, and caching live in
//! the client.

use std::future::Future;
use std::time::Duration;

use bytes::Bytes;

use crate::error::MdqError;

/// MIME type advertised in the `Accept` header for MDQ requests.
pub const SAML_METADATA_MIME: &str = "application/samlmetadata+xml";

/// Maximum metadata response body accepted, in bytes. The MDQ server is
/// untrusted, so an unbounded body would be a memory-exhaustion vector; 200 MiB
/// accommodates large federation aggregates such as eduGAIN while still putting
/// a hard ceiling on resource use.
pub const MAX_BODY_BYTES: usize = 200 * 1024 * 1024;

/// Maximum number of bytes read from a non-success response body for error
/// reporting. Error payloads are diagnostic only, so keep their footprint small
/// even when the metadata body cap is much larger.
const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;

/// Fetches raw metadata bytes from a URL.
///
/// Implementations should map a non-2xx response to [`MdqError::Http`] and any
/// connection/timeout/TLS failure to [`MdqError::Transport`].
pub trait MetadataFetcher {
    /// Perform an HTTP(S) GET and return the response body.
    fn fetch(&self, url: &str) -> impl Future<Output = Result<Bytes, MdqError>> + Send;
}

/// Default [`MetadataFetcher`] backed by [`reqwest`].
#[derive(Debug, Clone)]
pub struct ReqwestFetcher {
    client: reqwest::Client,
}

impl ReqwestFetcher {
    /// Create a fetcher with the given request timeout.
    pub fn with_timeout(timeout: Duration) -> Result<Self, MdqError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| MdqError::Transport(e.to_string()))?;
        Ok(Self { client })
    }

    /// Build a fetcher with the default 10s timeout, returning an error instead
    /// of panicking if the HTTP client cannot be constructed.
    ///
    /// Prefer this over [`ReqwestFetcher::default`] when the caller wants to
    /// handle TLS-backend / platform initialization failures explicitly rather
    /// than aborting the process.
    pub fn try_default() -> Result<Self, MdqError> {
        // A 10s timeout matches the Go reference.
        Self::with_timeout(Duration::from_secs(10))
    }

    /// Wrap a pre-built [`reqwest::Client`].
    pub fn from_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl Default for ReqwestFetcher {
    /// Build a fetcher with the default 10s timeout.
    ///
    /// # Panics
    ///
    /// Panics if the underlying HTTP client cannot be constructed (e.g. the TLS
    /// backend fails to initialize) — the same exceptional condition under which
    /// [`reqwest::Client::new`] itself panics. We deliberately do **not** fall
    /// back to reqwest's default client, because that follows redirects and
    /// would reopen the SSRF/redirect vector this fetcher closes. Use
    /// [`ReqwestFetcher::try_default`] to handle the failure explicitly.
    fn default() -> Self {
        Self::try_default().expect("failed to build default MDQ HTTP client")
    }
}

impl MetadataFetcher for ReqwestFetcher {
    async fn fetch(&self, url: &str) -> Result<Bytes, MdqError> {
        let mut resp = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, SAML_METADATA_MIME)
            .send()
            .await
            .map_err(|e| MdqError::Transport(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = read_error_body(&mut resp).await?;
            return Err(MdqError::Http {
                status: status.as_u16(),
                body: truncate(&body, 512),
            });
        }

        Ok(Bytes::from(read_body(&mut resp, MAX_BODY_BYTES).await?))
    }
}

async fn read_body(resp: &mut reqwest::Response, max_bytes: usize) -> Result<Vec<u8>, MdqError> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(MdqError::Transport(format!(
                "metadata response too large: {len} bytes (limit {max_bytes})"
            )));
        }
    }

    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| MdqError::Transport(e.to_string()))?
    {
        if buf.len() + chunk.len() > max_bytes {
            return Err(MdqError::Transport(format!(
                "metadata response exceeded {max_bytes}-byte limit"
            )));
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

async fn read_error_body(resp: &mut reqwest::Response) -> Result<String, MdqError> {
    let mut buf = Vec::new();
    let mut truncated = false;

    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| MdqError::Transport(e.to_string()))?
    {
        let remaining = MAX_ERROR_BODY_BYTES.saturating_sub(buf.len());
        if remaining == 0 {
            truncated = true;
            break;
        }
        if chunk.len() > remaining {
            buf.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        buf.extend_from_slice(&chunk);
    }

    let mut body = String::from_utf8_lossy(&buf).into_owned();
    if truncated {
        body.push_str("...[truncated]");
    }
    Ok(body)
}

/// Truncate a string to at most `max` bytes on a char boundary.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[tokio::test]
    async fn reqwest_fetcher_does_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/metadata\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
        });

        let fetcher = ReqwestFetcher::with_timeout(Duration::from_secs(1)).unwrap();
        let err = fetcher
            .fetch(&format!("http://{addr}/entities/example"))
            .await
            .unwrap_err();

        handle.join().unwrap();
        assert!(matches!(err, MdqError::Http { status: 302, .. }));
    }
}
