//! KMIP client -- connects to any KMIP 1.4 server via mTLS.
//!
//! Supports all 27 KMIP 1.4 operations.
//!
//! # Example
//!
//! ```no_run
//! use cyphera_kmip::KmipClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut client = KmipClient::new(
//!     "kmip-server.corp.internal",
//!     5696,
//!     "/path/to/client.pem",
//!     "/path/to/client-key.pem",
//!     Some("/path/to/ca.pem"),
//!     None,
//! )?;
//!
//! let key = client.fetch_key("my-key-name")?;
//! // key is a Vec<u8> of raw key bytes
//!
//! client.close();
//! # Ok(())
//! # }
//! ```

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::operations::*;
use crate::tags::{algorithm, tag};
use crate::ttlv::find_child;

/// Maximum KMIP response size (16MB).
const MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024;

/// KMIP Authentication credential for username/password auth.
#[derive(Clone)]
pub struct KmipCredential {
    pub username: String,
    pub password: String,
}

/// KMIP client for mTLS connections to KMIP servers.
///
/// # Thread Safety
///
/// `KmipClient` is `Send` but not `Sync`. For concurrent use, wrap in
/// `Arc<Mutex<KmipClient>>`.
pub struct KmipClient {
    host: String,
    port: u16,
    timeout: Duration,
    tls_config: Arc<ClientConfig>,
    stream: Option<StreamOwned<ClientConnection, TcpStream>>,
    credential: Option<KmipCredential>,
}

impl KmipClient {
    /// Create a new KMIP client.
    ///
    /// - `host` -- KMIP server hostname
    /// - `port` -- KMIP server port (default 5696)
    /// - `client_cert` -- path to client certificate PEM file
    /// - `client_key` -- path to client private key PEM file
    /// - `ca_cert` -- optional path to CA certificate PEM file
    /// - `timeout_ms` -- optional connection timeout in milliseconds (default 10000)
    pub fn new(
        host: &str,
        port: u16,
        client_cert: &str,
        client_key: &str,
        ca_cert: Option<&str>,
        timeout_ms: Option<u64>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cert_pem = fs::read(client_cert)?;
        let key_pem = fs::read(client_key)?;

        let certs = load_certs(&cert_pem)?;
        let key = load_private_key(&key_pem)?;

        let mut root_store = rustls::RootCertStore::empty();

        if let Some(ca_path) = ca_cert {
            let ca_pem = fs::read(ca_path)?;
            let ca_certs = load_certs(&ca_pem)?;
            for cert in ca_certs {
                root_store.add(cert)?;
            }
        } else {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        // Explicitly require TLS 1.3 minimum (fixes MEDIUM-B1)
        let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)?;

        Ok(KmipClient {
            host: host.to_string(),
            port,
            timeout: Duration::from_millis(timeout_ms.unwrap_or(10000)),
            tls_config: Arc::new(config),
            stream: None,
            credential: None,
        })
    }

    /// Set KMIP authentication credentials (username/password).
    /// Credentials are included in every request header when set (fixes MEDIUM-D2/M4).
    pub fn set_credentials(&mut self, username: &str, password: &str) {
        self.credential = Some(KmipCredential {
            username: username.to_string(),
            password: password.to_string(),
        });
    }

    /// Get the current credential (used by operations module).
    pub(crate) fn credential(&self) -> Option<&KmipCredential> {
        self.credential.as_ref()
    }

    // -----------------------------------------------------------------------
    // Core operations
    // -----------------------------------------------------------------------

    /// Locate keys by name.
    pub fn locate(&mut self, name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let request = build_locate_request(name, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Locate response")?;
        Ok(parse_locate_payload(&payload).unique_identifiers)
    }

    /// Get key material by unique ID.
    pub fn get(&mut self, unique_id: &str) -> Result<GetResult, Box<dyn std::error::Error>> {
        let request = build_get_request(unique_id, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Get response")?;
        Ok(parse_get_payload(&payload))
    }

    /// Create a new symmetric key on the server.
    pub fn create(
        &mut self,
        name: &str,
        algo: Option<&str>,
        length: Option<i32>,
    ) -> Result<CreateResult, Box<dyn std::error::Error>> {
        let algo_enum = resolve_algorithm(algo.unwrap_or("AES"));
        let algo_enum = if algo_enum == 0 { algorithm::AES } else { algo_enum };
        let request = build_create_request(name, algo_enum, length.unwrap_or(256), self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Create response")?;
        Ok(parse_create_payload(&payload))
    }

    /// Create a new asymmetric key pair on the server.
    pub fn create_key_pair(
        &mut self,
        name: &str,
        algo: u32,
        length: i32,
    ) -> Result<CreateKeyPairResult, Box<dyn std::error::Error>> {
        let request = build_create_key_pair_request(name, algo, length, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in CreateKeyPair response")?;
        Ok(parse_create_key_pair_payload(&payload))
    }

    /// Register existing key material on the server.
    pub fn register(
        &mut self,
        obj_type: u32,
        material: &[u8],
        name: &str,
        algo: u32,
        length: i32,
    ) -> Result<CreateResult, Box<dyn std::error::Error>> {
        let request = build_register_request(obj_type, material, name, algo, length, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Register response")?;
        Ok(parse_create_payload(&payload))
    }

    /// Re-key an existing key on the server.
    pub fn re_key(&mut self, unique_id: &str) -> Result<ReKeyResult, Box<dyn std::error::Error>> {
        let request = build_re_key_request(unique_id, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in ReKey response")?;
        Ok(parse_re_key_payload(&payload))
    }

    /// Derive a new key from an existing key.
    pub fn derive_key(
        &mut self,
        unique_id: &str,
        derivation_data: &[u8],
        name: &str,
        length: i32,
    ) -> Result<DeriveKeyResult, Box<dyn std::error::Error>> {
        let request = build_derive_key_request(unique_id, derivation_data, name, length, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in DeriveKey response")?;
        Ok(parse_derive_key_payload(&payload))
    }

    /// Check the status of a managed object.
    pub fn check(&mut self, unique_id: &str) -> Result<CheckResult, Box<dyn std::error::Error>> {
        let request = build_check_request(unique_id, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Check response")?;
        Ok(parse_check_payload(&payload))
    }

    /// Get all attributes of a managed object.
    pub fn get_attributes(&mut self, unique_id: &str) -> Result<GetResult, Box<dyn std::error::Error>> {
        let request = build_get_attributes_request(unique_id, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in GetAttributes response")?;
        Ok(parse_get_payload(&payload))
    }

    /// Get the list of attribute names for a managed object.
    pub fn get_attribute_list(&mut self, unique_id: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let request = build_get_attribute_list_request(unique_id, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        match response.payload {
            Some(ref payload) => {
                let attrs = crate::ttlv::find_children(payload, tag::ATTRIBUTE_NAME);
                Ok(attrs.iter().filter_map(|a| a.value.as_text().map(|s| s.to_string())).collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// Add an attribute to a managed object.
    pub fn add_attribute(&mut self, unique_id: &str, name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = build_add_attribute_request(unique_id, name, value, self.credential.as_ref());
        let response_data = self.send(&request)?;
        parse_response(&response_data)?;
        Ok(())
    }

    /// Modify an attribute of a managed object.
    pub fn modify_attribute(&mut self, unique_id: &str, name: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = build_modify_attribute_request(unique_id, name, value, self.credential.as_ref());
        let response_data = self.send(&request)?;
        parse_response(&response_data)?;
        Ok(())
    }

    /// Delete an attribute from a managed object.
    pub fn delete_attribute(&mut self, unique_id: &str, name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = build_delete_attribute_request(unique_id, name, self.credential.as_ref());
        let response_data = self.send(&request)?;
        parse_response(&response_data)?;
        Ok(())
    }

    /// Obtain a lease for a managed object. Returns lease time in seconds.
    pub fn obtain_lease(&mut self, unique_id: &str) -> Result<Option<u32>, Box<dyn std::error::Error>> {
        let request = build_obtain_lease_request(unique_id, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        match response.payload {
            Some(ref payload) => {
                let lease = find_child(payload, tag::LEASE_TIME)
                    .and_then(|i| i.value.as_integer().map(|v| v as u32));
                Ok(lease)
            }
            None => Ok(None),
        }
    }

    /// Activate a managed object.
    pub fn activate(&mut self, unique_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = build_activate_request(unique_id, self.credential.as_ref());
        let response_data = self.send(&request)?;
        parse_response(&response_data)?;
        Ok(())
    }

    /// Revoke a managed object with the given reason code.
    pub fn revoke(&mut self, unique_id: &str, reason: u32) -> Result<(), Box<dyn std::error::Error>> {
        let request = build_revoke_request(unique_id, reason, self.credential.as_ref());
        let response_data = self.send(&request)?;
        parse_response(&response_data)?;
        Ok(())
    }

    /// Destroy a managed object.
    pub fn destroy(&mut self, unique_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = build_destroy_request(unique_id, self.credential.as_ref());
        let response_data = self.send(&request)?;
        parse_response(&response_data)?;
        Ok(())
    }

    /// Archive a managed object.
    pub fn archive(&mut self, unique_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = build_archive_request(unique_id, self.credential.as_ref());
        let response_data = self.send(&request)?;
        parse_response(&response_data)?;
        Ok(())
    }

    /// Recover an archived managed object.
    pub fn recover(&mut self, unique_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let request = build_recover_request(unique_id, self.credential.as_ref());
        let response_data = self.send(&request)?;
        parse_response(&response_data)?;
        Ok(())
    }

    /// Query the server for supported operations and object types.
    pub fn query(&mut self) -> Result<QueryResult, Box<dyn std::error::Error>> {
        let request = build_query_request(self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Query response")?;
        Ok(parse_query_payload(&payload))
    }

    /// Poll the server.
    pub fn poll(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let request = build_poll_request(self.credential.as_ref());
        let response_data = self.send(&request)?;
        parse_response(&response_data)?;
        Ok(())
    }

    /// Discover KMIP versions supported by the server.
    pub fn discover_versions(&mut self) -> Result<DiscoverVersionsResult, Box<dyn std::error::Error>> {
        let request = build_discover_versions_request(self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in DiscoverVersions response")?;
        Ok(parse_discover_versions_payload(&payload))
    }

    /// Encrypt data using a managed key.
    pub fn encrypt(&mut self, unique_id: &str, data: &[u8]) -> Result<EncryptResult, Box<dyn std::error::Error>> {
        let request = build_encrypt_request(unique_id, data, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Encrypt response")?;
        Ok(parse_encrypt_payload(&payload))
    }

    /// Decrypt data using a managed key.
    pub fn decrypt(&mut self, unique_id: &str, data: &[u8], nonce: Option<&[u8]>) -> Result<DecryptResult, Box<dyn std::error::Error>> {
        let request = build_decrypt_request(unique_id, data, nonce, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Decrypt response")?;
        Ok(parse_decrypt_payload(&payload))
    }

    /// Sign data using a managed key.
    pub fn sign(&mut self, unique_id: &str, data: &[u8]) -> Result<SignResult, Box<dyn std::error::Error>> {
        let request = build_sign_request(unique_id, data, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Sign response")?;
        Ok(parse_sign_payload(&payload))
    }

    /// Verify a signature using a managed key.
    pub fn signature_verify(&mut self, unique_id: &str, data: &[u8], signature: &[u8]) -> Result<SignatureVerifyResult, Box<dyn std::error::Error>> {
        let request = build_signature_verify_request(unique_id, data, signature, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in SignatureVerify response")?;
        Ok(parse_signature_verify_payload(&payload))
    }

    /// Compute a MAC using a managed key.
    pub fn mac(&mut self, unique_id: &str, data: &[u8]) -> Result<MacResult, Box<dyn std::error::Error>> {
        let request = build_mac_request(unique_id, data, self.credential.as_ref());
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in MAC response")?;
        Ok(parse_mac_payload(&payload))
    }

    // -----------------------------------------------------------------------
    // Convenience methods
    // -----------------------------------------------------------------------

    /// Convenience: locate by name + get material in one call.
    /// Returns `Zeroizing<Vec<u8>>` — key material is automatically zeroed on drop.
    pub fn fetch_key(&mut self, name: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
        let ids = self.locate(name)?;
        if ids.is_empty() {
            return Err(format!("KMIP: no key found with name \"{}\"", name).into());
        }
        let result = self.get(&ids[0])?;
        result.key_material.ok_or_else(|| {
            format!(
                "KMIP: key \"{}\" ({}) has no extractable material",
                name, ids[0]
            )
            .into()
        })
    }

    /// Close the TLS connection.
    pub fn close(&mut self) {
        self.stream = None;
    }

    // -----------------------------------------------------------------------
    // Transport
    // -----------------------------------------------------------------------

    /// Send a KMIP request and receive the response.
    fn send(&mut self, request: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let stream = self.connect()?;
        if let Err(e) = stream.write_all(request).and_then(|_| stream.flush()) {
            self.stream = None; // Mark connection as stale.
            return Err(Box::new(e));
        }

        // Read the TTLV header (8 bytes) to determine total length
        let mut header = [0u8; 8];
        if let Err(e) = stream.read_exact(&mut header) {
            self.stream = None; // Mark connection as stale.
            return Err(Box::new(e));
        }

        let value_length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;

        // Validate response size before allocating.
        if value_length > MAX_RESPONSE_SIZE {
            self.stream = None; // Mark connection as stale.
            return Err(format!(
                "KMIP: response too large ({} bytes, max {})", value_length, MAX_RESPONSE_SIZE
            ).into());
        }

        let total_length = 8 + value_length;
        let mut buf = vec![0u8; total_length];
        buf[..8].copy_from_slice(&header);
        if let Err(e) = stream.read_exact(&mut buf[8..]) {
            self.stream = None; // Mark connection as stale.
            return Err(Box::new(e));
        }

        Ok(buf)
    }

    /// Establish or reuse the mTLS connection.
    fn connect(
        &mut self,
    ) -> Result<&mut StreamOwned<ClientConnection, TcpStream>, Box<dyn std::error::Error>> {
        if let Some(ref mut s) = self.stream {
            return Ok(s);
        }

        // Use ToSocketAddrs to support both hostnames and IP addresses (fixes HIGH-D1)
        use std::net::ToSocketAddrs;
        let addr = format!("{}:{}", self.host, self.port);
        let socket_addr = addr.to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "DNS resolution returned no addresses"))?;
        let tcp = TcpStream::connect_timeout(
            &socket_addr,
            self.timeout,
        )?;
        tcp.set_read_timeout(Some(self.timeout))?;
        tcp.set_write_timeout(Some(self.timeout))?;

        let server_name = self.host.clone().try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid DNS name")
        })?;

        let conn = ClientConnection::new(self.tls_config.clone(), server_name)?;
        let tls_stream = StreamOwned::new(conn, tcp);

        self.stream = Some(tls_stream);
        Ok(self.stream.as_mut().expect("stream was just assigned"))
    }
}

/// Resolve an algorithm name string to its KMIP enum value.
/// Returns 0 for unknown algorithms.
pub fn resolve_algorithm(name: &str) -> u32 {
    match name.to_uppercase().as_str() {
        "AES" => algorithm::AES,
        "DES" => algorithm::DES,
        "TRIPLEDES" | "3DES" => algorithm::TRIPLE_DES,
        "RSA" => algorithm::RSA,
        "DSA" => algorithm::DSA,
        "ECDSA" => algorithm::ECDSA,
        "HMACSHA1" => algorithm::HMAC_SHA1,
        "HMACSHA256" => algorithm::HMAC_SHA256,
        "HMACSHA384" => algorithm::HMAC_SHA384,
        "HMACSHA512" => algorithm::HMAC_SHA512,
        _ => 0,
    }
}

/// Securely zero a byte slice. Uses `zeroize` crate to prevent LLVM elision (fixes MEDIUM-C1).
pub fn zero_bytes(b: &mut [u8]) {
    use zeroize::Zeroize;
    b.zeroize();
}

/// Load PEM certificates from bytes.
fn load_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let mut reader = io::BufReader::new(pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// Load a PEM private key from bytes.
fn load_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let mut reader = io::BufReader::new(pem);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or("No private key found in PEM")?;
    Ok(key)
}
