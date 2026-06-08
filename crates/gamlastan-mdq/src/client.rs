//! The MDQ client: dynamic per-entity queries plus static file/URL modes.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};

use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{Key, KeysManager};
use gamlastan::metadata::{
    CachedMetadata, EntityDescriptor, MetadataCache, MetadataError, MetadataStore,
};

use crate::error::MdqError;
use crate::fetch::{MetadataFetcher, ReqwestFetcher};
use crate::transform::{request_path, MdqTransform};
use crate::verify::{parse_verify_select, Resolved};

/// Default cache lifetime used when a document carries no `cacheDuration`.
const DEFAULT_TTL: Duration = Duration::from_secs(3600);
/// Initial backoff after a static-URL fetch failure.
const RETRY_BASE: Duration = Duration::from_secs(5);
/// Maximum backoff between static-URL retries.
const RETRY_MAX: Duration = Duration::from_secs(120);

/// Which role descriptor the fetched metadata must contain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RequiredRole {
    /// Accept any entity (no role gating).
    #[default]
    Any,
    /// Require an `IDPSSODescriptor`.
    Idp,
    /// Require an `SPSSODescriptor`.
    Sp,
}

/// Federation metadata-signing trust material (zero or more certs).
#[derive(Debug, Clone)]
pub(crate) struct Trust {
    certs: KeysManager,
    has_certs: bool,
}

impl Trust {
    fn new() -> Self {
        Self {
            certs: KeysManager::new(),
            has_certs: false,
        }
    }

    pub(crate) fn has_certs(&self) -> bool {
        self.has_certs
    }

    pub(crate) fn keys(&self) -> &KeysManager {
        &self.certs
    }

    fn add_key(&mut self, key: Key) {
        if let Some(der) = key.x509_chain.first().cloned() {
            self.certs.add_trusted_cert(der);
        }
        self.certs.add_key(key);
        self.has_certs = true;
    }

    fn add_pem(&mut self, pem: &[u8]) -> Result<(), MdqError> {
        let key = loader::load_x509_cert_pem(pem).map_err(|e| MdqError::Cert(e.to_string()))?;
        self.add_key(key);
        Ok(())
    }

    fn add_der(&mut self, der: Vec<u8>) -> Result<(), MdqError> {
        let key = loader::load_x509_cert_der(&der).map_err(|e| MdqError::Cert(e.to_string()))?;
        self.add_key(key);
        Ok(())
    }
}

/// A controllable clock; defaults to [`Utc::now`].
type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// State for a static (single-entity) client backed by a file or URL.
struct StaticState {
    entity_id: String,
    metadata: Option<EntityDescriptor>,
    valid_until: Option<DateTime<Utc>>,
    /// Set only for URL-backed static metadata not yet loaded (lazy retry).
    source_url: Option<String>,
    retry_after: DateTime<Utc>,
    retry_backoff: Duration,
}

/// A SAML Metadata Query Protocol (MDQ) client.
///
/// In **dynamic** mode it queries `server_url + transform(entityID)`, verifying
/// (when signing certs are configured) and caching per the document's
/// `validUntil`/`cacheDuration` (E94) with a fallback TTL. In **static** mode it
/// serves a single entity loaded from a file or URL (URL failures retry lazily
/// with exponential backoff).
///
/// The client is generic over a [`MetadataFetcher`]; production code uses the
/// default [`ReqwestFetcher`].
///
/// ```no_run
/// use gamlastan_mdq::{MdqClient, RequiredRole};
///
/// # async fn run() -> Result<(), gamlastan_mdq::MdqError> {
/// let client = MdqClient::new("https://mdq.example.org/")
///     .require_role(RequiredRole::Sp);
/// let entity = client.get("https://sp.example.com/shibboleth").await?;
/// println!("{}", entity.entity_id);
/// # Ok(())
/// # }
/// ```
pub struct MdqClient<F = ReqwestFetcher> {
    fetcher: F,
    server_url: String,
    transform: MdqTransform,
    required_role: RequiredRole,
    trust: Trust,
    /// Permit accepting metadata that cannot be signature-verified (no certs).
    /// Off by default: a no-cert client refuses metadata unless this is set.
    allow_unverified: bool,
    fallback_ttl: Duration,
    clock: Clock,
    cache: Arc<Mutex<MetadataCache>>,
    warned_unverified: Arc<AtomicBool>,
    static_state: Option<Arc<Mutex<StaticState>>>,
}

fn default_clock() -> Clock {
    Arc::new(Utc::now)
}

fn normalize_server_url(mut url: String) -> String {
    if !url.is_empty() && !url.ends_with('/') {
        url.push('/');
    }
    url
}

impl MdqClient<ReqwestFetcher> {
    /// Create a dynamic MDQ client for `server_url` using the default
    /// reqwest-based transport (10s timeout).
    pub fn new(server_url: impl Into<String>) -> Self {
        Self::with_fetcher(server_url, ReqwestFetcher::default())
    }
}

impl<F: MetadataFetcher> MdqClient<F> {
    /// Create a dynamic MDQ client with a custom transport.
    pub fn with_fetcher(server_url: impl Into<String>, fetcher: F) -> Self {
        Self {
            fetcher,
            server_url: normalize_server_url(server_url.into()),
            transform: MdqTransform::default(),
            required_role: RequiredRole::Any,
            trust: Trust::new(),
            allow_unverified: false,
            fallback_ttl: DEFAULT_TTL,
            clock: default_clock(),
            cache: Arc::new(Mutex::new(MetadataCache::new())),
            warned_unverified: Arc::new(AtomicBool::new(false)),
            static_state: None,
        }
    }

    /// Select the entityID → request-path transform (default: URL-encoded).
    pub fn with_transform(mut self, transform: MdqTransform) -> Self {
        self.transform = transform;
        self
    }

    /// Require a specific role descriptor in fetched metadata (default: `Any`).
    pub fn require_role(mut self, role: RequiredRole) -> Self {
        self.required_role = role;
        self
    }

    /// Allow accepting metadata that cannot be signature-verified because no
    /// signing certificate is configured.
    ///
    /// **Insecure:** the MDQ server is untrusted, so without a trust anchor the
    /// returned metadata has no authenticity guarantee. By default a client with
    /// no certs refuses such metadata ([`MdqError::VerificationNotConfigured`]);
    /// this opts into the unverified mode explicitly (e.g. local testing). Has no
    /// effect once a signing cert is configured — those documents are always
    /// verified.
    pub fn allow_unverified(mut self) -> Self {
        self.allow_unverified = true;
        self
    }

    /// Add a federation metadata-signing certificate (PEM). May be called
    /// repeatedly for key rollover. When ≥1 cert is configured, every fetched
    /// document must carry a valid signature.
    pub fn add_signing_cert_pem(mut self, pem: &[u8]) -> Result<Self, MdqError> {
        self.trust.add_pem(pem)?;
        Ok(self)
    }

    /// Add a federation metadata-signing certificate (DER).
    pub fn add_signing_cert_der(mut self, der: Vec<u8>) -> Result<Self, MdqError> {
        self.trust.add_der(der)?;
        Ok(self)
    }

    /// Set the fallback cache lifetime used when a document has no
    /// `cacheDuration` (default: 1 hour).
    pub fn with_fallback_ttl(mut self, ttl: Duration) -> Self {
        self.fallback_ttl = ttl;
        self
    }

    /// Override the clock (for tests). Defaults to [`Utc::now`].
    pub fn with_clock<C>(mut self, clock: C) -> Self
    where
        C: Fn() -> DateTime<Utc> + Send + Sync + 'static,
    {
        self.clock = Arc::new(clock);
        self
    }

    /// Convert this client into a static one serving a single entity loaded
    /// from a local metadata file. Role/trust settings configured so far are
    /// applied during the load.
    pub fn into_static_file(
        mut self,
        path: impl AsRef<Path>,
        entity_id: impl Into<String>,
    ) -> Result<Self, MdqError> {
        let entity_id = entity_id.into();
        let xml = std::fs::read_to_string(path).map_err(|e| MdqError::Io(e.to_string()))?;
        self.maybe_warn_unverified();
        let resolved = parse_verify_select(
            &xml,
            &entity_id,
            &self.trust,
            self.required_role,
            self.allow_unverified,
            (self.clock)(),
        )?;
        self.static_state = Some(Arc::new(Mutex::new(StaticState {
            entity_id,
            metadata: Some(resolved.entity),
            valid_until: resolved.valid_until,
            source_url: None,
            retry_after: (self.clock)(),
            retry_backoff: RETRY_BASE,
        })));
        Ok(self)
    }

    /// Convert this client into a static one serving a single entity fetched
    /// from `url`. If the initial fetch fails the client is still returned and
    /// retries lazily (exponential backoff) on the next [`get`](Self::get).
    pub async fn into_static_url(
        mut self,
        url: impl Into<String>,
        entity_id: impl Into<String>,
    ) -> Self {
        let url = url.into();
        let entity_id = entity_id.into();
        let state = match self.try_load_static(&url, &entity_id).await {
            Ok(resolved) => StaticState {
                entity_id,
                metadata: Some(resolved.entity),
                valid_until: resolved.valid_until,
                source_url: Some(url.clone()),
                retry_after: (self.clock)(),
                retry_backoff: RETRY_BASE,
            },
            Err(e) => {
                log::error!("static MDQ metadata fetch failed, will retry lazily: {e}");
                let retry_after = (self.clock)() + chrono_backoff(RETRY_BASE);
                StaticState {
                    entity_id,
                    metadata: None,
                    valid_until: None,
                    source_url: Some(url),
                    retry_after,
                    retry_backoff: RETRY_BASE,
                }
            }
        };
        self.static_state = Some(Arc::new(Mutex::new(state)));
        self
    }

    /// Fetch metadata for `entity_id`.
    ///
    /// In static mode the `entity_id` argument is ignored (the configured
    /// entity is returned); a differing value is logged.
    pub async fn get(&self, entity_id: &str) -> Result<EntityDescriptor, MdqError> {
        if let Some(state) = self.static_state.clone() {
            self.get_static(&state, entity_id).await
        } else {
            self.get_dynamic(entity_id).await
        }
    }

    /// Drop all cached entries (dynamic mode).
    pub fn clear_cache(&self) {
        let mut cache = lock(&self.cache);
        *cache = MetadataCache::new();
    }

    /// Number of cached entries (dynamic mode).
    pub fn cache_len(&self) -> usize {
        lock(&self.cache).len()
    }

    /// Whether this client is in static (single-entity) mode.
    pub fn is_static(&self) -> bool {
        self.static_state.is_some()
    }

    /// The configured static entityID, if any.
    pub fn static_entity_id(&self) -> Option<String> {
        self.static_state
            .as_ref()
            .map(|s| lock(s).entity_id.clone())
    }

    // ── internals ──────────────────────────────────────────────────────────

    async fn get_dynamic(&self, entity_id: &str) -> Result<EntityDescriptor, MdqError> {
        let now = (self.clock)();

        // Cache check — lock is dropped before any await.
        {
            let cache = lock(&self.cache);
            if let Some(cached) = cache.get(entity_id) {
                if !cached.should_refresh(now) {
                    return Ok(cached.metadata.clone());
                }
            }
        }

        self.maybe_warn_unverified();

        let url = request_path(&self.server_url, entity_id, self.transform);
        let bytes = self.fetcher.fetch(&url).await?;
        let xml = std::str::from_utf8(&bytes).map_err(|e| MdqError::NotUtf8(e.to_string()))?;
        let resolved = parse_verify_select(
            xml,
            entity_id,
            &self.trust,
            self.required_role,
            self.allow_unverified,
            now,
        )?;

        let cache_duration = resolved.cache_duration.or(Some(self.fallback_ttl));
        let cached = CachedMetadata::new(
            resolved.entity.clone(),
            now,
            cache_duration,
            resolved.valid_until,
        );
        {
            let mut cache = lock(&self.cache);
            cache.put(entity_id.to_string(), cached);
        }
        Ok(resolved.entity)
    }

    async fn get_static(
        &self,
        state: &Arc<Mutex<StaticState>>,
        requested: &str,
    ) -> Result<EntityDescriptor, MdqError> {
        // Snapshot under the lock, then release before any await.
        let (loaded, valid_until, source_url, configured_id, retry_after) = {
            let s = lock(state);
            (
                s.metadata.clone(),
                s.valid_until,
                s.source_url.clone(),
                s.entity_id.clone(),
                s.retry_after,
            )
        };

        let now = (self.clock)();

        if let Some(meta) = loaded {
            if is_valid_at(valid_until, now) {
                if !requested.is_empty() && requested != configured_id {
                    log::info!(
                        "requested entityID {requested:?} differs from static IdP {configured_id:?}"
                    );
                }
                return Ok(meta);
            }
            if source_url.is_none() {
                return Err(expired_metadata_error(valid_until));
            }
        }

        let url = source_url
            .ok_or_else(|| MdqError::StaticUnavailable("static metadata not configured".into()))?;

        if now < retry_after {
            return Err(MdqError::StaticUnavailable(format!(
                "next retry at {}",
                retry_after.to_rfc3339()
            )));
        }

        match self.try_load_static(&url, &configured_id).await {
            Ok(resolved) => {
                let mut s = lock(state);
                s.metadata = Some(resolved.entity.clone());
                s.valid_until = resolved.valid_until;
                s.source_url = Some(url);
                s.retry_after = now;
                s.retry_backoff = RETRY_BASE;
                Ok(resolved.entity)
            }
            Err(e) => {
                let mut s = lock(state);
                let next = (s.retry_backoff * 2).min(RETRY_MAX);
                s.retry_backoff = next;
                s.retry_after = now + chrono_backoff(next);
                Err(MdqError::StaticUnavailable(format!("fetch failed: {e}")))
            }
        }
    }

    async fn try_load_static(
        &self,
        url: &str,
        entity_id: &str,
    ) -> Result<Resolved, MdqError> {
        let bytes = self.fetcher.fetch(url).await?;
        let xml = std::str::from_utf8(&bytes).map_err(|e| MdqError::NotUtf8(e.to_string()))?;
        self.maybe_warn_unverified();
        parse_verify_select(
            xml,
            entity_id,
            &self.trust,
            self.required_role,
            self.allow_unverified,
            (self.clock)(),
        )
    }

    fn maybe_warn_unverified(&self) {
        if self.allow_unverified
            && !self.trust.has_certs()
            && !self.warned_unverified.swap(true, Ordering::Relaxed)
        {
            log::warn!(
                "MDQ client has no signing certificate configured and runs in \
                 allow_unverified mode; fetched metadata will NOT be \
                 signature-verified"
            );
        }
    }
}

/// Lock a mutex, recovering the guard even if a previous holder panicked.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Convert a backoff `Duration` into a `chrono::Duration`, clamped to the max.
fn chrono_backoff(d: Duration) -> chrono::Duration {
    chrono::Duration::from_std(d)
        .unwrap_or_else(|_| chrono::Duration::seconds(RETRY_MAX.as_secs() as i64))
}

fn is_valid_at(valid_until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    match valid_until {
        Some(valid_until) => now < valid_until,
        None => true,
    }
}

fn expired_metadata_error(valid_until: Option<DateTime<Utc>>) -> MdqError {
    MdqError::Metadata(MetadataError::Expired(
        valid_until
            .map(|valid_until| valid_until.to_rfc3339())
            .unwrap_or_else(|| "unknown".to_string()),
    ))
}
