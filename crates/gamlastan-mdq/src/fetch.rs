//! HTTP transport abstraction for fetching metadata.
//!
//! The MDQ client is generic over a [`MetadataFetcher`] so that production code
//! uses [`ReqwestFetcher`] while tests inject a deterministic mock. The trait
//! deliberately deals in raw bytes — parsing, verification, and caching live in
//! the client.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::error::MdqError;

/// MIME type advertised in the `Accept` header for MDQ requests.
pub const SAML_METADATA_MIME: &str = "application/samlmetadata+xml";

/// Maximum metadata response body accepted, in bytes. The MDQ server is
/// untrusted, so an unbounded body would be a memory-exhaustion vector. The
/// conservative default targets per-entity MDQ responses; aggregate consumers
/// must opt into a larger cap with [`ReqwestFetcher::with_limits`].
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
/// Maximum number of response bodies buffered concurrently by default.
pub const MAX_CONCURRENT_FETCHES: usize = 8;

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
    max_body_bytes: usize,
    permits: Arc<tokio::sync::Semaphore>,
}

impl ReqwestFetcher {
    /// Create a fetcher with the given request timeout.
    pub fn with_timeout(timeout: Duration) -> Result<Self, MdqError> {
        Self::with_limits(timeout, MAX_BODY_BYTES, MAX_CONCURRENT_FETCHES)
    }

    /// Create a fetcher with explicit per-response and concurrency limits.
    ///
    /// `max_body_bytes` bounds each buffered response and
    /// `max_concurrent_fetches` bounds simultaneous response buffering. Large
    /// aggregate consumers can deliberately raise the body cap while the ready
    /// MDQ path retains a conservative per-entity default.
    ///
    /// # Errors
    ///
    /// Returns [`MdqError::Transport`] if either limit is zero or the HTTP
    /// client cannot be constructed.
    pub fn with_limits(
        timeout: Duration,
        max_body_bytes: usize,
        max_concurrent_fetches: usize,
    ) -> Result<Self, MdqError> {
        if max_body_bytes == 0 || max_concurrent_fetches == 0 {
            return Err(MdqError::Transport(
                "MDQ body and concurrency limits must be non-zero".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| MdqError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            max_body_bytes,
            permits: Arc::new(tokio::sync::Semaphore::new(max_concurrent_fetches)),
        })
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
        Self::from_client_with_limits(client, MAX_BODY_BYTES, MAX_CONCURRENT_FETCHES)
            .expect("default MDQ limits are non-zero")
    }

    /// Wrap a pre-built client while applying explicit resource limits.
    ///
    /// `max_body_bytes` bounds each response body and
    /// `max_concurrent_fetches` bounds simultaneous response buffering.
    ///
    /// # Errors
    ///
    /// Returns [`MdqError::Transport`] if either limit is zero.
    pub fn from_client_with_limits(
        client: reqwest::Client,
        max_body_bytes: usize,
        max_concurrent_fetches: usize,
    ) -> Result<Self, MdqError> {
        if max_body_bytes == 0 || max_concurrent_fetches == 0 {
            return Err(MdqError::Transport(
                "MDQ body and concurrency limits must be non-zero".into(),
            ));
        }
        Ok(Self {
            client,
            max_body_bytes,
            permits: Arc::new(tokio::sync::Semaphore::new(max_concurrent_fetches)),
        })
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
        let _permit = self
            .permits
            .acquire()
            .await
            .map_err(|_| MdqError::Transport("MDQ fetch limiter closed".into()))?;
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

        Ok(Bytes::from(
            read_body(&mut resp, self.max_body_bytes).await?,
        ))
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

    /// Verifies that zero-valued resource limits fail during construction.
    #[test]
    fn reqwest_fetcher_rejects_zero_limits() {
        assert!(ReqwestFetcher::with_limits(Duration::from_secs(1), 0, 1).is_err());
        assert!(ReqwestFetcher::with_limits(Duration::from_secs(1), 1, 0).is_err());
    }
}
