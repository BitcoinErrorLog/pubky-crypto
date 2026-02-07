//! Pure cryptographic primitives for the Pubky ecosystem.
//!
//! This crate provides the core cryptographic operations used across
//! pubky-noise, paykit-rs, atomicity-core, and other Pubky crates:
//!
//! - **Sealed Blob** (v1/v2): Authenticated encryption for stored delivery
//! - **SB2**: Binary wire format for Sealed Blob v2
//! - **UKD**: Unified Key Delegation (AppCert, KeyBinding, typed signing)
//! - **KDF**: Key derivation functions (HKDF-SHA256/SHA512)
//! - **Ed25519 helpers**: Signing and verification
//! - **X25519 helpers**: Key generation, public key derivation
//! - **Secure memory**: Best-effort mlock for key material (feature-gated)
//!
//! ## Design Principles
//!
//! - No networking, no async, no transport dependencies
//! - All errors use [`CryptoError`] (higher-level crates map to their own error types)
//! - Pure computation only — suitable for use in Ring (no network access)

pub mod ed25519_helpers;
pub mod errors;
pub mod kdf;
pub mod sealed_blob;
pub mod sealed_blob_v2;
#[cfg(feature = "secure-mem")]
pub mod secure_mem;
pub mod ukd;

// Re-export commonly used types at crate root
pub use ed25519_helpers::{ed25519_sign, ed25519_verify};
pub use errors::{CryptoError, CryptoResult};
pub use kdf::{derive_noise_seed, derive_x25519_for_device_epoch, x25519_pk_from_sk, shared_secret_nonzero};
pub use sealed_blob::{
    is_sealed_blob, sealed_blob_decrypt, sealed_blob_encrypt, x25519_generate_keypair,
    x25519_public_from_secret, SealedBlobEnvelope, MAX_PLAINTEXT_SIZE, SEALED_BLOB_VERSION,
    NONCE_SIZE_V2,
};
pub use sealed_blob_v2::{
    build_aad as sb2_build_aad, compute_sig_input as sb2_compute_sig_input, Sb2, Sb2Header,
    AAD_PREFIX as SB2_AAD_PREFIX, MAX_HEADER_LEN, MAX_MSG_ID_LEN, SB2_MAGIC, SB2_VERSION,
};
pub use ukd::{
    derive_cert_id, generate_app_keypair, issue_app_cert, sign_typed_content, verify_app_cert,
    verify_typed_content, AppCert, AppCertInput, AppKeyEntry, InboxKeyEntry, KeyBinding,
    TransportKeyEntry, CERT_ID_LEN,
};
