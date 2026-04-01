# gamlastan

A comprehensive, pure-Rust SAML 2.0 library implementing the full specification with errata05 corrections.

## Features

- **Zero-copy parsing** -- Borrowed `FooRef<'a>` types reference the XML buffer directly; owned `Foo` types for construction and storage
- **Full SAML 2.0 type system** -- Assertions, protocol messages, metadata, status codes, name identifiers
- **XML integration** -- Built on [uppsala](https://crates.io/crates/uppsala) for XML parsing and serialization
- **Cryptographic operations** -- XML-DSig signing/verification, XML Encryption, via [bergshamra](https://crates.io/crates/bergshamra)
- **All protocol bindings** -- HTTP Redirect, HTTP POST, HTTP Artifact, SOAP, PAOS, URI
- **32-check assertion validator** -- Comprehensive security validation suite
- **All SAML 2.0 profiles** -- Web Browser SSO (SP + IdP), Single Logout, ECP, Artifact Resolution, Name ID Management/Mapping, IdP Discovery, Assertion Query
- **Attribute profiles** -- Basic, X.500/LDAP, UUID, DCE PAC
- **SPID compliant** -- Passes 263/263 Italian SPID conformance checks
- **Errata05** -- Implements all 65 SAML 2.0 errata corrections

## Modules

| Module | Description |
|--------|-------------|
| `core` | SAML 2.0 types, constants, identifiers |
| `xml` | XML parsing (`SamlDeserialize`) and serialization (`SamlSerialize`) via uppsala |
| `crypto` | Signing, verification, encryption, decryption via bergshamra |
| `metadata` | `EntityDescriptor`, caching, validation, endpoint resolution |
| `bindings` | HTTP Redirect, POST, Artifact, SOAP, PAOS, URI, RelayState |
| `security` | Assertion validator, replay cache, clock skew, audience restriction |
| `profiles` | Web Browser SSO, SLO, ECP, Artifact Resolution, and more |

## Zero-copy dual-type pattern

Every SAML data type has two variants:

```rust
// Borrowed -- all fields are &'a str, zero heap allocation during parsing
let response_ref: ResponseRef<'_> = parse_saml(&doc)?;

// Owned -- all fields are String, for construction and long-lived storage
let response: Response = response_ref.to_owned();
```

## Usage

Parse and validate a SAML Response:

```rust
use gamlastan::xml::uppsala;
use gamlastan::xml::deserialize::parse_saml;
use gamlastan::core::protocol::response::ResponseRef;

let doc = uppsala::parse(xml_str)?;
let response: ResponseRef<'_> = parse_saml(&doc)?;
assert!(response.base.status.is_success());
```

Build and serialize an AuthnRequest:

```rust
use gamlastan::profiles::sso::web_browser::AuthnRequestOptions;
use gamlastan::profiles::sso::sp::create_authn_request;
use gamlastan::xml::serialize::SamlSerialize;

let options = AuthnRequestOptions {
    issuer: "https://sp.example.com".to_string(),
    destination: "https://idp.example.com/sso".to_string(),
    acs_url: "https://sp.example.com/acs".to_string(),
    ..Default::default()
};
let request = create_authn_request(&options);
let xml = request.to_xml_string()?;
```

## Web framework integration

See [gamlastan-actix](https://crates.io/crates/gamlastan-actix) for ready-to-use actix-web extractors, responders, and SP/IdP handlers.

## License

BSD-2-Clause
