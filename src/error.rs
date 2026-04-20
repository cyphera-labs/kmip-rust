use std::fmt;
use std::io;

/// Typed error for KMIP client operations (fixes LOW-D4/L3).
///
/// Allows callers to match on error variants to distinguish transport errors
/// (retryable) from protocol errors (not retryable) from parse errors.
#[derive(Debug)]
pub enum KmipClientError {
    /// Transport-level error (TCP, DNS, timeout). Likely retryable.
    Transport(io::Error),
    /// TLS handshake or certificate error.
    Tls(String),
    /// KMIP protocol error (server returned an error result).
    Protocol {
        status: Option<u32>,
        reason: Option<u32>,
        message: Option<String>,
    },
    /// TTLV parsing error (malformed response).
    Parse(String),
    /// Other error.
    Other(String),
}

impl fmt::Display for KmipClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KmipClientError::Transport(e) => write!(f, "KMIP transport error: {}", e),
            KmipClientError::Tls(e) => write!(f, "KMIP TLS error: {}", e),
            KmipClientError::Protocol { status, reason, message } => {
                write!(f, "KMIP protocol error: status={:?}, reason={:?}, message={:?}", status, reason, message)
            }
            KmipClientError::Parse(e) => write!(f, "KMIP parse error: {}", e),
            KmipClientError::Other(e) => write!(f, "KMIP error: {}", e),
        }
    }
}

impl std::error::Error for KmipClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KmipClientError::Transport(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for KmipClientError {
    fn from(e: io::Error) -> Self {
        KmipClientError::Transport(e)
    }
}

impl From<String> for KmipClientError {
    fn from(e: String) -> Self {
        KmipClientError::Other(e)
    }
}

impl From<&str> for KmipClientError {
    fn from(e: &str) -> Self {
        KmipClientError::Other(e.to_string())
    }
}
