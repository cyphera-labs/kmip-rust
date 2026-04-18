//! KMIP client -- connects to any KMIP 1.4 server via mTLS.
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
use crate::tags::algorithm;

/// KMIP client for mTLS connections to KMIP servers.
pub struct KmipClient {
    host: String,
    port: u16,
    timeout: Duration,
    tls_config: Arc<ClientConfig>,
    stream: Option<StreamOwned<ClientConnection, TcpStream>>,
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

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)?;

        Ok(KmipClient {
            host: host.to_string(),
            port,
            timeout: Duration::from_millis(timeout_ms.unwrap_or(10000)),
            tls_config: Arc::new(config),
            stream: None,
        })
    }

    /// Locate keys by name.
    pub fn locate(&mut self, name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let request = build_locate_request(name);
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Locate response")?;
        Ok(parse_locate_payload(&payload).unique_identifiers)
    }

    /// Get key material by unique ID.
    pub fn get(&mut self, unique_id: &str) -> Result<GetResult, Box<dyn std::error::Error>> {
        let request = build_get_request(unique_id);
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
        let algo_enum = match algo {
            Some("AES") | Some("aes") | None => algorithm::AES,
            Some("DES") | Some("des") => algorithm::DES,
            Some("TripleDES") | Some("3DES") => algorithm::TRIPLE_DES,
            Some("RSA") | Some("rsa") => algorithm::RSA,
            _ => algorithm::AES,
        };
        let request = build_create_request(name, algo_enum, length.unwrap_or(256));
        let response_data = self.send(&request)?;
        let response = parse_response(&response_data)?;
        let payload = response.payload.ok_or("No payload in Create response")?;
        Ok(parse_create_payload(&payload))
    }

    /// Convenience: locate by name + get material in one call.
    pub fn fetch_key(&mut self, name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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

    /// Send a KMIP request and receive the response.
    fn send(&mut self, request: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let stream = self.connect()?;
        stream.write_all(request)?;
        stream.flush()?;

        // Read the TTLV header (8 bytes) to determine total length
        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;

        let value_length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let total_length = 8 + value_length;

        let mut buf = vec![0u8; total_length];
        buf[..8].copy_from_slice(&header);
        stream.read_exact(&mut buf[8..])?;

        Ok(buf)
    }

    /// Establish or reuse the mTLS connection.
    fn connect(
        &mut self,
    ) -> Result<&mut StreamOwned<ClientConnection, TcpStream>, Box<dyn std::error::Error>> {
        if self.stream.is_some() {
            return Ok(self.stream.as_mut().unwrap());
        }

        let addr = format!("{}:{}", self.host, self.port);
        let tcp = TcpStream::connect_timeout(
            &addr.parse()?,
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
        Ok(self.stream.as_mut().unwrap())
    }
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
