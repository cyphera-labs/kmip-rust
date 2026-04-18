# kmip-rust

[![CI](https://github.com/cyphera-labs/kmip-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/kmip-rust/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/kmip-rust/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/kmip-rust/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

KMIP client for Rust -- connect to any KMIP-compliant key management server.

Supports Thales CipherTrust, IBM SKLM, Entrust KeyControl, Fortanix, HashiCorp Vault Enterprise, and any KMIP 1.4 server.

```toml
[dependencies]
cyphera-kmip = "0.1"
```

## Quick Start

```rust
use cyphera_kmip::KmipClient;

let mut client = KmipClient::new(
    "kmip-server.corp.internal",
    5696,
    "/path/to/client.pem",
    "/path/to/client-key.pem",
    Some("/path/to/ca.pem"),
    None,
)?;

// Fetch a key by name (locate + get in one call)
let key = client.fetch_key("my-encryption-key")?;
// key is a Vec<u8> of raw key bytes (e.g., 32 bytes for AES-256)

// Or step by step:
let ids = client.locate("my-key")?;
let result = client.get(&ids[0])?;
println!("{:?}", result.key_material);

// Create a new AES-256 key on the server
let created = client.create("new-key-name", Some("AES"), Some(256))?;
println!("{}", created.unique_identifier.unwrap());

client.close();
```

## Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Locate | `client.locate(name)` | Find keys by name, returns unique IDs |
| Get | `client.get(id)` | Fetch key material by unique ID |
| Create | `client.create(name, algo, length)` | Create a new symmetric key |
| Fetch | `client.fetch_key(name)` | Locate + Get in one call |

## Authentication

KMIP uses mutual TLS (mTLS). Provide:
- **Client certificate** -- identifies your application to the KMS
- **Client private key** -- proves ownership of the certificate
- **CA certificate** -- validates the KMS server's certificate

```rust
let mut client = KmipClient::new(
    "kmip.corp.internal",
    5696,                              // default KMIP port
    "/etc/kmip/client.pem",
    "/etc/kmip/client-key.pem",
    Some("/etc/kmip/ca.pem"),
    Some(10000),                       // connection timeout (ms)
)?;
```

## TTLV Codec

The low-level TTLV (Tag-Type-Length-Value) encoder/decoder is also exported for advanced use:

```rust
use cyphera_kmip::ttlv::*;
use cyphera_kmip::tags::tag;

// Build custom KMIP messages
let msg = encode_structure(tag::REQUEST_MESSAGE, &[/* ... */]);

// Parse raw KMIP responses
let parsed = decode_ttlv(&response_bytes, 0).unwrap();
```

## Supported KMS Servers

| Server | KMIP Version | Tested |
|--------|-------------|--------|
| Thales CipherTrust Manager | 1.x, 2.0 | Planned |
| IBM SKLM | 1.x, 2.0 | Planned |
| Entrust KeyControl | 1.x, 2.0 | Planned |
| Fortanix DSM | 2.0 | Planned |
| HashiCorp Vault Enterprise | 1.4 | Planned |
| PyKMIP (test server) | 1.0-2.0 | CI |

## Zero External Dependencies (for TLS)

This library uses `rustls` for TLS -- no OpenSSL or system TLS dependency required.

## Status

Alpha. KMIP 1.4 operations: Locate, Get, Create.

## License

Apache 2.0 -- Copyright 2026 Horizon Digital Engineering LLC
