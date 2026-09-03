# gamlastan-actix

SAML 2.0 integration for [actix-web](https://actix.rs/), built on [gamlastan](https://crates.io/crates/gamlastan).

Provides ready-to-use extractors, responders, handlers, and middleware for implementing SAML Service Provider (SP) and Identity Provider (IdP) endpoints.

## Architecture

Three layers of abstraction:

1. **Adapters** (`request_adapter`, `response_adapter`) -- Low-level bridges between actix-web and gamlastan's framework-agnostic binding traits.
2. **Extractors & Responders** (`extractors`, `responders`) -- `FromRequest` and `Responder` implementations for actix-web handler signatures.
3. **Handlers** (`sp`, `idp`) -- Ready-to-use SP and IdP route handlers registered with `configure_sp()` / `configure_idp()`.

## SP Quick Start

```rust,no_run
use actix_web::{web, App, HttpServer};
use gamlastan_actix::{SloCallback, SpConfig, sp::configure_sp};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load IdP metadata (from file, URL, etc.)
    let idp_metadata = todo!("parse IdP metadata XML");

    let sp_config = SpConfig::new(
        "https://sp.example.com",        // SP entity ID
        "https://sp.example.com/acs",    // ACS URL
        idp_metadata,
    )
    .with_slo_url("https://sp.example.com/slo")
    .with_metadata_url("https://sp.example.com/metadata");

    let config = web::Data::new(sp_config);
    let slo_callback: SloCallback = Box::new(|event, request| Box::pin(async move {
        let _ = (event, request);
        // Await durable local-session invalidation here. Returning an error
        // prevents gamlastan from reporting protocol success.
        Ok(())
    }));
    let slo_callback = web::Data::new(slo_callback);

    HttpServer::new(move || {
        App::new()
            .app_data(config.clone())
            .app_data(slo_callback.clone())
            .configure(configure_sp)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

> **HTTPS is required for solicited login and logout.** The ready SP binds
> every AuthnRequest and LogoutRequest to the initiating browser with a
> `Secure`, `HttpOnly`
> `__Host-gamlastan_authn_state` cookie (five-minute lifetime, matching the
> request-tracker TTL). Browsers only store `Secure` cookies over HTTPS, so an
> SP served over plain HTTP — including local development — never receives the
> cookie back and every solicited response is rejected. Terminate TLS in front
> of the SP (or serve HTTPS directly) in every environment. IdP-initiated SSO
> responses must be enabled explicitly with
> `SecurityConfig::allow_unsolicited_responses`.

The SLO callback is asynchronous and fallible so applications can await an
external session store. It should make invalidation durable and idempotent
before returning `Ok(())`. On `Err`, gamlastan returns no SAML success, but the
message's replay or correlation reservation remains terminal and cannot be
retried.

## IdP Quick Start

```rust,no_run
use std::sync::Arc;
use actix_web::{web, App, HttpServer};
use gamlastan_actix::{AuthnCallback, IdpConfig, IdpSigningContext, idp::configure_idp};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Parse and validate the SP's metadata before registering its SSO role.
    let trusted_sp = todo!("load trusted SP metadata");
    let config = IdpConfig::new(
        "https://idp.example.com",       // IdP entity ID
        "https://idp.example.com/sso",   // SSO URL
    )
    .with_signing_cert("base64-encoded-DER-cert")
    .with_trusted_sp("https://sp.example.com", trusted_sp);

    // Set up signing context with your private key
    let signing_ctx: Arc<IdpSigningContext> = todo!("load signing key");
    // Authenticate the request and return the subject, attributes, and session data.
    let authn_callback: AuthnCallback = Box::new(|processed, request| {
        todo!("authenticate the user for {processed:?} and {request:?}")
    });

    let config = web::Data::new(config);
    let signing = web::Data::new(signing_ctx);
    let authn_callback = web::Data::new(authn_callback);

    HttpServer::new(move || {
        App::new()
            .app_data(config.clone())
            .app_data(signing.clone())
            .app_data(authn_callback.clone())
            .configure(configure_idp)
    })
    .bind("0.0.0.0:9443")?
    .run()
    .await
}
```

## Features

- **SP handlers** -- Login initiation, ACS (Response processing), SLO, metadata generation
- **IdP handlers** -- SSO (AuthnRequest processing + Response creation), SLO, artifact resolution, metadata generation
- **Automatic binding detection** -- `SamlMessage` extractor auto-detects HTTP Redirect, POST, Artifact, SOAP, and PAOS bindings
- **Response/Assertion signing** -- `IdpSigningContext` with enveloped XML-DSig (inner-to-outer signing order)
- **Signed metadata** -- Both SP and IdP metadata endpoints produce signed XML
- **RelayState forwarding** -- Extracted from incoming requests and forwarded in responses
- **Authentication callback** -- IdP SSO handler delegates user authentication to an application-provided `AuthnCallback`
- **SAML auth middleware** -- Optional `SamlAuth` middleware for protecting routes

## License

BSD-2-Clause
