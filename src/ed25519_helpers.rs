//! Ed25519 signing and verification helpers.
//!
//! General-purpose Ed25519 operations extracted from pubky-noise for use
//! by any crate in the Pubky ecosystem.

use crate::errors::CryptoError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Sign an arbitrary message with an Ed25519 secret key.
///
/// This is a general-purpose signing function for use cases like:
/// - Push relay authentication
/// - Subscription signing
/// - Any operation requiring Ed25519 signatures
///
/// # Arguments
///
/// * `ed25519_secret` - 32-byte Ed25519 secret key (seed)
/// * `message` - Arbitrary message bytes to sign
///
/// # Returns
///
/// 64-byte Ed25519 signature, or error if key is invalid.
pub fn ed25519_sign(ed25519_secret: &[u8; 32], message: &[u8]) -> Result<[u8; 64], CryptoError> {
    let signing_key = SigningKey::from_bytes(ed25519_secret);
    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes())
}

/// Verify an Ed25519 signature.
///
/// # Arguments
///
/// * `ed25519_public` - 32-byte Ed25519 public key
/// * `message` - Original message bytes
/// * `signature` - 64-byte signature to verify
///
/// # Returns
///
/// `true` if signature is valid, `false` otherwise.
pub fn ed25519_verify(ed25519_public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(ed25519_public) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(message, &sig).is_ok()
}
