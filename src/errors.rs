//! Error types for pubky-crypto.
//!
//! `CryptoError` covers all pure-crypto failure modes. Higher-level crates
//! (e.g., pubky-noise) define their own error enums and implement
//! `From<CryptoError>` to integrate seamlessly.

use thiserror::Error;

/// Result type for crypto operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Errors originating from pure cryptographic operations.
///
/// This enum intentionally excludes transport/network/session concerns,
/// which belong in pubky-noise's `NoiseError`.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key derivation failure (HKDF, device_id validation, etc.)
    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    /// Serialization / deserialization error (CBOR, JSON).
    #[error("serialization error: {0}")]
    Serde(String),

    /// Invalid peer key (low-order X25519 point or all-zeros DH result).
    #[error("invalid peer static or shared secret")]
    InvalidPeerKey,

    /// AEAD decryption failure or envelope parse error.
    #[error("decryption error: {0}")]
    Decryption(String),

    /// Ed25519 signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,

    /// Catch-all for other crypto errors.
    #[error("crypto error: {0}")]
    Other(String),
}

impl From<serde_json::Error> for CryptoError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e.to_string())
    }
}
