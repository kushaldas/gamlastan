// SAML 2.0 actix-web configuration.
//
// Provides SpConfig and IdpConfig for registering SAML endpoints.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use gamlastan::bindings::traits::ArtifactStore;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeysManager, SamlVerifier};
use gamlastan::metadata::types::entity_descriptor::EntityDescriptor;
use gamlastan::metadata::types::sp::SpSsoDescriptor;
use gamlastan::profiles::session::SessionStore;
use gamlastan::security::config::SecurityConfig;
use gamlastan::security::replay::{InMemoryReplayCache, ReplayCache};

/// A Service Provider this IdP trusts.
///
/// The ready IdP handlers use these descriptors to bind request-supplied values
/// to known SP metadata: the requested AssertionConsumerServiceURL (so an
/// attacker cannot redirect a signed assertion to an ACS they control), and the
/// SP signing keys used to authenticate back-channel ArtifactResolve and
/// front-channel LogoutRequest messages before any state is mutated.
#[derive(Clone)]
pub struct TrustedSp {
    /// The SP `entityID` (matched against the message `Issuer`).
    pub entity_id: String,
    /// The SP's SSO descriptor (ACS endpoints, signing certificates).
    pub sp_sso: SpSsoDescriptor,
}

/// Future returned by [`TrustedSpResolver::resolve_sp`].
pub type ResolveSpFuture<'a> = Pin<Box<dyn Future<Output = Option<SpSsoDescriptor>> + Send + 'a>>;

/// Resolves trusted SP metadata by `entityID` at request time.
///
/// In a federation the IdP usually does **not** know its partner SPs statically;
/// it learns their metadata from a Metadata Query (MDQ) server or an aggregate
/// feed, keyed by `entityID`. Implement this trait (typically over a
/// `gamlastan_mdq::MdqClient`) and register it with
/// [`IdpConfig::with_sp_resolver`] so the ready SSO/SLO/artifact handlers can
/// obtain trusted SP metadata dynamically instead of failing closed.
///
/// The ready handlers consult the static [`IdpConfig::trusted_sps`] registry
/// first and fall back to this resolver. The resolver is responsible for its own
/// trust decisions — for MDQ that means verifying the metadata signature against
/// the federation's trust anchor before returning a descriptor (the MDQ client
/// does this when configured with signing certificates). Returning `None` means
/// "this entityID is not a trusted SP", and the handler then fails closed.
///
/// `gamlastan-actix` deliberately does not depend on `gamlastan-mdq`; the
/// application wires the two together.
///
/// # Examples
///
/// ```ignore
/// use std::sync::Arc;
/// use gamlastan_actix::{IdpConfig, ResolveSpFuture, TrustedSpResolver};
/// use gamlastan_mdq::MdqClient;
///
/// // An MdqClient configured with `.require_role(RequiredRole::Sp)` and the
/// // federation signing certificate(s), so `get` verifies the metadata
/// // signature against the trust anchor before returning it.
/// struct MdqSpResolver(Arc<MdqClient>);
///
/// impl TrustedSpResolver for MdqSpResolver {
///     fn resolve_sp<'a>(&'a self, entity_id: &'a str) -> ResolveSpFuture<'a> {
///         Box::pin(async move {
///             self.0
///                 .get(entity_id)
///                 .await
///                 .ok()
///                 .and_then(|ed| ed.sp_sso_descriptors().first().cloned())
///         })
///     }
/// }
///
/// let resolver = Arc::new(MdqSpResolver(mdq_client));
/// let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
///     .with_sp_resolver(resolver);
/// ```
pub trait TrustedSpResolver: Send + Sync {
    /// Resolve the SP metadata for `entity_id`, or `None` if it is not trusted.
    fn resolve_sp<'a>(&'a self, entity_id: &'a str) -> ResolveSpFuture<'a>;
}

/// Service Provider configuration for SAML integration.
///
/// Holds the SP's identity, endpoints, partner IdP metadata,
/// security settings, and replay cache. Pass this via `actix_web::web::Data`.
#[derive(Clone)]
pub struct SpConfig {
    /// SP entity ID (the Issuer in AuthnRequests).
    pub entity_id: String,

    /// Assertion Consumer Service URL (where the IdP sends responses).
    pub acs_url: String,

    /// Single Logout URL.
    pub slo_url: String,

    /// SP metadata URL.
    pub metadata_url: String,

    /// Partner IdP metadata (for endpoint discovery and verification).
    pub idp_metadata: EntityDescriptor,

    /// Security configuration (clock skew, signature requirements, etc.).
    pub security: SecurityConfig,

    /// Replay cache for one-time-use assertion ID enforcement.
    pub replay_cache: Arc<dyn ReplayCache>,

    /// Whether to require signed assertions.
    pub want_assertions_signed: bool,

    /// NameID format to request (None = let IdP decide).
    pub name_id_format: Option<String>,

    /// Whether to allow the IdP to create new identifiers (E14).
    pub allow_create: bool,

    /// ForceAuthn default (None = don't include).
    pub force_authn: Option<bool>,

    /// IsPassive default (None = don't include).
    pub is_passive: Option<bool>,

    /// Protocol binding to request for the response.
    pub protocol_binding: Option<String>,

    /// Request ID tracker for InResponseTo verification.
    /// Stores sent AuthnRequest IDs so responses can be correlated.
    pub request_id_tracker: Arc<dyn RequestIdTracker>,
}

/// Tracks outgoing AuthnRequest IDs for InResponseTo verification.
///
/// When the SP sends an AuthnRequest, the request ID is stored.
/// When a Response arrives, the InResponseTo is checked against stored IDs.
pub trait RequestIdTracker: Send + Sync {
    /// Record a sent AuthnRequest ID with its creation timestamp.
    fn store(&self, request_id: &str);
    /// Check if a request ID was sent and consume it (one-time use).
    /// Returns true if the ID was found and removed.
    fn consume(&self, request_id: &str) -> bool;
}

/// In-memory request ID tracker with automatic expiry.
pub struct InMemoryRequestIdTracker {
    /// Map of request_id -> insertion time (for TTL)
    ids: Mutex<HashMap<String, std::time::Instant>>,
    /// TTL for stored request IDs (default: 5 minutes)
    ttl: std::time::Duration,
}

impl InMemoryRequestIdTracker {
    /// Create a new tracker with the default TTL of 5 minutes.
    pub fn new() -> Self {
        Self {
            ids: Mutex::new(HashMap::new()),
            ttl: std::time::Duration::from_secs(300),
        }
    }

    /// Create a new tracker with a custom TTL.
    pub fn with_ttl(ttl: std::time::Duration) -> Self {
        Self {
            ids: Mutex::new(HashMap::new()),
            ttl,
        }
    }
}

impl Default for InMemoryRequestIdTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestIdTracker for InMemoryRequestIdTracker {
    fn store(&self, request_id: &str) {
        let mut ids = self.ids.lock().unwrap();
        // Purge expired entries while we're here
        let now = std::time::Instant::now();
        ids.retain(|_, inserted| now.duration_since(*inserted) < self.ttl);
        ids.insert(request_id.to_string(), now);
    }

    fn consume(&self, request_id: &str) -> bool {
        let mut ids = self.ids.lock().unwrap();
        ids.remove(request_id).is_some()
    }
}

impl SpConfig {
    /// Create a minimal SP configuration.
    pub fn new(
        entity_id: impl Into<String>,
        acs_url: impl Into<String>,
        idp_metadata: EntityDescriptor,
    ) -> Self {
        let entity_id = entity_id.into();
        let acs_url = acs_url.into();
        Self {
            slo_url: String::new(),
            metadata_url: String::new(),
            idp_metadata,
            security: SecurityConfig::default(),
            replay_cache: Arc::new(InMemoryReplayCache::new()),
            want_assertions_signed: true,
            name_id_format: None,
            allow_create: false,
            force_authn: None,
            is_passive: None,
            protocol_binding: None,
            request_id_tracker: Arc::new(InMemoryRequestIdTracker::new()),
            entity_id,
            acs_url,
        }
    }

    /// Set the SLO URL.
    pub fn with_slo_url(mut self, url: impl Into<String>) -> Self {
        self.slo_url = url.into();
        self
    }

    /// Set the metadata URL.
    pub fn with_metadata_url(mut self, url: impl Into<String>) -> Self {
        self.metadata_url = url.into();
        self
    }

    /// Set the security configuration.
    pub fn with_security(mut self, security: SecurityConfig) -> Self {
        self.security = security;
        self
    }

    /// Set a custom replay cache.
    pub fn with_replay_cache(mut self, cache: Arc<dyn ReplayCache>) -> Self {
        self.replay_cache = cache;
        self
    }
}

/// Identity Provider configuration for SAML integration.
///
/// Holds the IdP's identity, signing config, and partner SP metadata.
/// Pass this via `actix_web::web::Data`.
pub struct IdpConfig {
    /// IdP entity ID (the Issuer in Responses/Assertions).
    pub entity_id: String,

    /// SSO service URL (where SPs send AuthnRequests).
    pub sso_url: String,

    /// Single Logout URL.
    pub slo_url: String,

    /// IdP metadata URL.
    pub metadata_url: String,

    /// Security configuration.
    pub security: SecurityConfig,

    /// Default assertion lifetime in seconds.
    pub assertion_lifetime_seconds: u64,

    /// Default session lifetime in seconds.
    pub session_lifetime_seconds: u64,

    /// Whether to sign responses.
    pub sign_responses: bool,

    /// Whether to sign assertions.
    pub sign_assertions: bool,

    /// Optional base64-encoded DER signing certificate for IdP metadata.
    ///
    /// When a signing context is registered, its certificate is used for
    /// response/assertion `KeyInfo` and as the preferred metadata
    /// `KeyDescriptor`. This config value is mainly a fallback for metadata when
    /// no signing context is present.
    pub signing_cert_b64: Option<String>,

    /// Session store for tracking IdP sessions and participants.
    /// Required for SLO propagation. If None, logout propagation is skipped.
    pub session_store: Option<Arc<dyn SessionStore>>,

    /// Artifact store for HTTP Artifact binding resolution.
    /// If None, artifact resolution returns an error response.
    pub artifact_store: Option<Arc<dyn ArtifactStore + Send + Sync>>,

    /// Service providers this IdP trusts statically. The ready SSO/SLO/artifact
    /// handlers fail closed when the relevant trust material is absent: an
    /// AuthnRequest whose issuer/ACS is not described here (and not resolvable
    /// via [`sp_resolver`](IdpConfig::sp_resolver)) is refused, and unsigned or
    /// untrusted ArtifactResolve / LogoutRequest messages are rejected.
    pub trusted_sps: Vec<TrustedSp>,

    /// Optional dynamic resolver for trusted SP metadata, consulted when an SP is
    /// not in [`trusted_sps`](IdpConfig::trusted_sps). This is how a federation
    /// IdP with an MDQ setup (and no statically registered SPs) provides trust:
    /// the resolver fetches and signature-verifies SP metadata by `entityID` at
    /// request time. Without either source, the ready handlers fail closed.
    pub sp_resolver: Option<Arc<dyn TrustedSpResolver>>,

    /// Escape hatch for deployments that authenticate the SAML SOAP back-channel
    /// and front-channel at the transport layer (e.g. mutual TLS) instead of via
    /// message signatures. When `false` (the default), the ready artifact and SLO
    /// handlers require a signature from a trusted SP before acting. Only set
    /// this `true` if the transport already authenticates the requester.
    pub allow_unauthenticated_backchannel: bool,
}

impl IdpConfig {
    /// Create a minimal IdP configuration.
    pub fn new(entity_id: impl Into<String>, sso_url: impl Into<String>) -> Self {
        Self {
            entity_id: entity_id.into(),
            sso_url: sso_url.into(),
            slo_url: String::new(),
            metadata_url: String::new(),
            security: SecurityConfig::default(),
            assertion_lifetime_seconds: 300,
            session_lifetime_seconds: 28800, // 8 hours
            sign_responses: true,
            sign_assertions: true,
            signing_cert_b64: None,
            session_store: None,
            artifact_store: None,
            trusted_sps: Vec::new(),
            sp_resolver: None,
            allow_unauthenticated_backchannel: false,
        }
    }

    /// Set the SLO URL.
    pub fn with_slo_url(mut self, url: impl Into<String>) -> Self {
        self.slo_url = url.into();
        self
    }

    /// Set the metadata URL.
    pub fn with_metadata_url(mut self, url: impl Into<String>) -> Self {
        self.metadata_url = url.into();
        self
    }

    /// Set the security configuration.
    pub fn with_security(mut self, security: SecurityConfig) -> Self {
        self.security = security;
        self
    }

    /// Set the signing certificate (base64-encoded DER).
    pub fn with_signing_cert(mut self, cert_b64: impl Into<String>) -> Self {
        self.signing_cert_b64 = Some(cert_b64.into());
        self
    }

    /// Set the session store for SLO propagation.
    pub fn with_session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.session_store = Some(store);
        self
    }

    /// Set the artifact store for HTTP Artifact binding resolution.
    pub fn with_artifact_store(mut self, store: Arc<dyn ArtifactStore + Send + Sync>) -> Self {
        self.artifact_store = Some(store);
        self
    }

    /// Register a Service Provider this IdP trusts (builder style).
    ///
    /// The ready IdP handlers consult the registered SPs to make the SSO, SLO,
    /// and artifact-resolution endpoints fail closed:
    ///
    /// - **SSO** binds the request `Issuer` to a trusted SP and validates the
    ///   request-supplied `AssertionConsumerServiceURL` against that SP's
    ///   metadata, so an attacker cannot have a signed assertion delivered to an
    ///   ACS URL they control.
    /// - **SLO / Artifact** verify the message signature against the trusted SP's
    ///   signing certificates before mutating session state or consuming an
    ///   artifact.
    ///
    /// `entity_id` is matched against the message `Issuer`; `sp_sso` is the SP's
    /// SSO descriptor (typically parsed from the SP's metadata document).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use gamlastan_actix::IdpConfig;
    /// # use gamlastan::metadata::types::sp::SpSsoDescriptor;
    /// # let sp_sso: SpSsoDescriptor = unimplemented!("parsed from SP metadata");
    /// let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
    ///     .with_trusted_sp("https://sp.example.com", sp_sso);
    /// assert!(config.trusted_sp("https://sp.example.com").is_some());
    /// ```
    pub fn with_trusted_sp(
        mut self,
        entity_id: impl Into<String>,
        sp_sso: SpSsoDescriptor,
    ) -> Self {
        self.trusted_sps.push(TrustedSp {
            entity_id: entity_id.into(),
            sp_sso,
        });
        self
    }

    /// Register a dynamic [`TrustedSpResolver`] (builder style), typically backed
    /// by an MDQ client, so the ready handlers can obtain trusted SP metadata for
    /// federations where SPs are not statically registered.
    ///
    /// The handlers check [`trusted_sps`](IdpConfig::trusted_sps) first, then this
    /// resolver. See [`TrustedSpResolver`] for an MDQ-backed example.
    pub fn with_sp_resolver(mut self, resolver: Arc<dyn TrustedSpResolver>) -> Self {
        self.sp_resolver = Some(resolver);
        self
    }

    /// Opt into transport-authenticated back-channel/front-channel operation
    /// (builder style).
    ///
    /// When set to `true` *and* no trusted SPs are registered, the ready SLO and
    /// artifact-resolution handlers skip the message-signature requirement,
    /// trusting that the transport (e.g. mutual TLS) has already authenticated
    /// the requester. Leave this at its default (`false`) unless that is
    /// genuinely the case — otherwise the endpoints accept unauthenticated
    /// destructive requests. See
    /// [`allow_unauthenticated_backchannel`](IdpConfig::allow_unauthenticated_backchannel).
    ///
    /// # Examples
    ///
    /// ```
    /// # use gamlastan_actix::IdpConfig;
    /// // Deployment terminates mutual TLS in front of the IdP.
    /// let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
    ///     .allow_unauthenticated_backchannel(true);
    /// ```
    pub fn allow_unauthenticated_backchannel(mut self, allow: bool) -> Self {
        self.allow_unauthenticated_backchannel = allow;
        self
    }

    /// Look up a registered trusted SP's SSO descriptor by `entityID`.
    ///
    /// Returns `None` when no SP with that entityID has been registered via
    /// [`with_trusted_sp`](IdpConfig::with_trusted_sp); callers in the ready
    /// handlers treat `None` as "untrusted" and fail closed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use gamlastan_actix::IdpConfig;
    /// let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
    /// assert!(config.trusted_sp("https://sp.example.com").is_none());
    /// ```
    pub fn trusted_sp(&self, entity_id: &str) -> Option<&SpSsoDescriptor> {
        self.trusted_sps
            .iter()
            .find(|sp| sp.entity_id == entity_id)
            .map(|sp| &sp.sp_sso)
    }

    /// Build an XML-DSig verifier from the signing certificates of every
    /// registered trusted SP.
    ///
    /// The ready SLO and artifact-resolution handlers use this to authenticate
    /// incoming `LogoutRequest`/`ArtifactResolve` messages. Each trusted SP's
    /// signing certificates are added both as verification keys and as trusted
    /// certificates, and the verifier inherits the configured `ds:Object`
    /// (E91) rejection policy.
    ///
    /// Returns `None` when no trusted SP exposes a usable signing certificate —
    /// in which case the caller fails closed unless
    /// [`allow_unauthenticated_backchannel`](IdpConfig::allow_unauthenticated_backchannel)
    /// is set. An empty result deliberately does not distinguish "no SPs
    /// registered" from "registered SPs had unparseable KeyInfo": both mean
    /// "cannot authenticate the requester", and both must fail closed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use gamlastan_actix::IdpConfig;
    /// // With no trusted SPs, there is nothing to verify against.
    /// let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
    /// assert!(config.trusted_sp_verifier().is_none());
    /// ```
    pub fn trusted_sp_verifier(&self) -> Option<SamlVerifier> {
        let mut keys = KeysManager::new();
        for sp in &self.trusted_sps {
            self.add_sp_keys(&mut keys, &sp.sp_sso);
        }
        self.finish_verifier(keys)
    }

    /// Build an XML-DSig verifier from a single SP's signing certificates.
    ///
    /// Used by the ready SLO and artifact-resolution handlers to authenticate a
    /// message against the *specific* SP that issued it — whether that SP was
    /// registered statically ([`with_trusted_sp`](IdpConfig::with_trusted_sp)) or
    /// resolved dynamically via a [`TrustedSpResolver`] (e.g. MDQ). Only the
    /// issuing SP's key should verify its message, so this is preferred over
    /// [`trusted_sp_verifier`](IdpConfig::trusted_sp_verifier) for that purpose.
    ///
    /// Returns `None` when the SP exposes no usable signing certificate, in which
    /// case the caller fails closed.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use gamlastan_actix::IdpConfig;
    /// # use gamlastan::metadata::types::sp::SpSsoDescriptor;
    /// # let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
    /// # let sp: SpSsoDescriptor = unimplemented!();
    /// if let Some(verifier) = config.verifier_for(&sp) {
    ///     // verify the incoming message against this SP's key
    /// }
    /// ```
    pub fn verifier_for(&self, sp: &SpSsoDescriptor) -> Option<SamlVerifier> {
        let mut keys = KeysManager::new();
        self.add_sp_keys(&mut keys, sp);
        self.finish_verifier(keys)
    }

    /// Add an SP's signing certificates to `keys` as both verification keys and
    /// trusted certificates.
    fn add_sp_keys(&self, keys: &mut KeysManager, sp: &SpSsoDescriptor) {
        for cert in sp.signing_certificates_der() {
            if let Ok(key) = loader::load_x509_cert_der(&cert) {
                keys.add_key(key);
                keys.add_trusted_cert(cert);
            }
        }
    }

    /// Wrap a populated `KeysManager` in a verifier honouring the E91 policy, or
    /// `None` when no trusted certificate was loaded.
    fn finish_verifier(&self, keys: KeysManager) -> Option<SamlVerifier> {
        keys.has_trusted_certs().then(|| {
            SamlVerifier::with_ds_object_rejection(
                keys,
                self.security.reject_signatures_with_ds_object,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gamlastan::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};

    fn make_dummy_entity_descriptor() -> EntityDescriptor {
        EntityDescriptor {
            entity_id: "https://idp.example.com".to_string(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![],
                sp_sso: vec![],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        }
    }

    #[test]
    fn test_sp_config_new() {
        let config = SpConfig::new(
            "https://sp.example.com",
            "https://sp.example.com/acs",
            make_dummy_entity_descriptor(),
        );
        assert_eq!(config.entity_id, "https://sp.example.com");
        assert_eq!(config.acs_url, "https://sp.example.com/acs");
        assert!(config.want_assertions_signed);
        assert!(config.slo_url.is_empty());
    }

    #[test]
    fn test_sp_config_builder() {
        let config = SpConfig::new(
            "https://sp.example.com",
            "https://sp.example.com/acs",
            make_dummy_entity_descriptor(),
        )
        .with_slo_url("https://sp.example.com/slo")
        .with_metadata_url("https://sp.example.com/metadata");

        assert_eq!(config.slo_url, "https://sp.example.com/slo");
        assert_eq!(config.metadata_url, "https://sp.example.com/metadata");
    }

    #[test]
    fn test_idp_config_new() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        assert_eq!(config.entity_id, "https://idp.example.com");
        assert_eq!(config.sso_url, "https://idp.example.com/sso");
        assert_eq!(config.assertion_lifetime_seconds, 300);
        assert!(config.sign_responses);
    }

    #[test]
    fn test_idp_config_builder() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_slo_url("https://idp.example.com/slo")
            .with_metadata_url("https://idp.example.com/metadata");

        assert_eq!(config.slo_url, "https://idp.example.com/slo");
        assert_eq!(config.metadata_url, "https://idp.example.com/metadata");
    }

    #[test]
    fn test_idp_config_defaults_no_stores() {
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso");
        assert!(config.session_store.is_none());
        assert!(config.artifact_store.is_none());
    }

    #[test]
    fn test_idp_config_with_session_store() {
        use gamlastan::profiles::session::InMemorySessionStore;
        let store = Arc::new(InMemorySessionStore::new());
        let config = IdpConfig::new("https://idp.example.com", "https://idp.example.com/sso")
            .with_session_store(store);
        assert!(config.session_store.is_some());
    }

    #[test]
    fn test_request_id_tracker_store_and_consume() {
        let tracker = InMemoryRequestIdTracker::new();
        tracker.store("_req_123");
        tracker.store("_req_456");

        // First consume should succeed
        assert!(tracker.consume("_req_123"));
        // Second consume should fail (already consumed)
        assert!(!tracker.consume("_req_123"));
        // Other ID still available
        assert!(tracker.consume("_req_456"));
    }

    #[test]
    fn test_request_id_tracker_consume_unknown() {
        let tracker = InMemoryRequestIdTracker::new();
        assert!(!tracker.consume("_nonexistent"));
    }

    #[test]
    fn test_request_id_tracker_ttl_expiry() {
        let tracker = InMemoryRequestIdTracker::with_ttl(std::time::Duration::from_millis(1));
        tracker.store("_req_expire");

        // Wait for TTL to expire
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Should be expired — store triggers purge of expired entries
        tracker.store("_req_new");
        assert!(!tracker.consume("_req_expire"));
        assert!(tracker.consume("_req_new"));
    }

    #[test]
    fn test_request_id_tracker_default() {
        let tracker = InMemoryRequestIdTracker::default();
        tracker.store("_req_default");
        assert!(tracker.consume("_req_default"));
    }

    #[test]
    fn test_sp_config_has_request_id_tracker() {
        let config = SpConfig::new(
            "https://sp.example.com",
            "https://sp.example.com/acs",
            make_dummy_entity_descriptor(),
        );
        // Default tracker should be InMemoryRequestIdTracker
        config.request_id_tracker.store("_test_id");
        assert!(config.request_id_tracker.consume("_test_id"));
        assert!(!config.request_id_tracker.consume("_test_id"));
    }
}
