# gamlastan-mdq

A client for the SAML **Metadata Query Protocol (MDQ)** — fetch SAML entity
metadata on demand by `entityID` instead of loading every metadata file at
startup. It is a thin async layer over the pure metadata/crypto building blocks
in [`gamlastan`].

## Features

- **Dynamic MDQ queries** — `GET {server_url}/{transform(entityID)}` with
  `Accept: application/samlmetadata+xml`, then parse, verify, and cache.
- **Static modes** — serve a single entity from a local file or a URL; URL
  fetch failures retry lazily with exponential backoff (5s → 2min).
- **Role-agnostic** with an optional `RequiredRole` gate (`Any` / `Idp` / `Sp`).
- **Two entityID transforms** — percent-encoded (default) and the `{sha1}`
  transform (`{sha1}` + hex SHA-1 of the entityID), for interop with different
  MDQ servers (e.g. pyFF / thiss.io).
- **Signature verification** against zero or more federation signing
  certificates (PEM/DER, supports key rollover). When ≥1 cert is configured,
  unsigned or invalid metadata is rejected. With no cert, fetched metadata is
  rejected unless the caller explicitly opts into `allow_unverified()` for local
  testing.
- **E94-aware caching** — honors the document's `validUntil` (hard validity) and
  `cacheDuration` (refresh hint), with a configurable fallback TTL, via
  `gamlastan`'s `MetadataCache`.
- **Aggregate responses** — accepts a single `<EntityDescriptor>` or an
  `<EntitiesDescriptor>` (verifies the aggregate signature, then selects the
  child whose entityID matches the request).
- **Pluggable transport** — generic over a `MetadataFetcher` trait, so tests
  inject a deterministic mock (the default is a `reqwest`-based fetcher).
- **Fail-closed default transport** — the default `ReqwestFetcher` does not
  follow HTTP redirects from untrusted MDQ responses.

## Usage

```rust,no_run
use gamlastan_mdq::{MdqClient, MdqTransform, RequiredRole};

# async fn run(federation_cert_pem: &[u8]) -> Result<(), gamlastan_mdq::MdqError> {
// Dynamic MDQ: resolve an SP's metadata on demand, verifying the federation
// signature and requiring an SPSSODescriptor.
let client = MdqClient::new("https://mdq.example.org/")
    .require_role(RequiredRole::Sp)
    .add_signing_cert_pem(federation_cert_pem)?;

let sp = client.get("https://sp.example.com/shibboleth").await?;
println!("{}", sp.entity_id);
# Ok(())
# }
```

Static single-entity modes (file at startup, or URL with lazy retry):

```rust,no_run
use gamlastan_mdq::{MdqClient, RequiredRole};

# async fn run() -> Result<(), gamlastan_mdq::MdqError> {
let from_file = MdqClient::new("")
    .require_role(RequiredRole::Idp)
    .into_static_file("idp-metadata.xml", "https://idp.example.com/idp")?;

let from_url = MdqClient::new("")
    .into_static_url("https://idp.example.com/metadata", "https://idp.example.com/idp")
    .await;
# Ok(())
# }
```

## Design notes

- The pure parse/verify/cache logic lives in `gamlastan::metadata`; this crate
  only adds the async HTTP fetch, retry/backoff, transform, and orchestration.
  The core `gamlastan` crate stays free of `reqwest`/`tokio`.
- Concurrent cache-miss fetches for the same entityID are **not** de-duplicated
  (no single-flight): under load, several concurrent misses may each issue a
  request until one populates the cache. The cache lock is never held across an
  `.await`.
- The clock is injectable (`with_clock`) so cache expiry and retry backoff are
  deterministically testable; it defaults to `chrono::Utc::now`.

## Testing

```sh
cargo test -p gamlastan-mdq
```

Most HTTP is mocked and time is driven by a controllable clock, so the suite is
deterministic. The default transport has one localhost-only regression test that
proves redirects are not followed.

[`gamlastan`]: ../gamlastan
