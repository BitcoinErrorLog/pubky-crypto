# Pubky Stack Adjustments Plan

Apply Antoine's advice by tightening stack layering (smallest possible crypto/key surface), clarifying authentication domains, and cleaning up Paykit naming/API duplication.

## Target Architecture

Both Ring and Paykit depend on pubky-noise, which depends on pubky-crypto.

## Task List

- [ ] Scaffold pubky-crypto with Cargo.toml (v0.1.0)
- [ ] Rename AuthenticatedTransport to HomeserverSessionStorage
- [ ] Rename snapshot APIs to supported methods index
- [ ] Move SB2/UKD/KDF/errors from pubky-noise into pubky-crypto
- [ ] Update pubky-ring bridges
- [ ] Update Atomicity spec naming

See full plan at: .cursor/plans/paykit-stack-adjustments_28679450.plan.md

## Goals

- Make the **security boundary crisp**: smallest possible code surface that holds/uses secret keys
- Clarify the **two authentication domains** (Noise peer auth vs homeserver session auth) in naming
- Remove confusing terminology like "snapshot" for supported payment method publication
- Reduce redundancy by extracting reusable primitives

## Why Ring needs pubky-noise (not just pubky-crypto)

Ring requires **live P2P sessions** for:
- Cross-device pairing (Ring on phone A to Bitkit on phone B)
- Real-time key delegation handoffs
- Secure interactive key-binding ceremonies

These require Noise Protocol handshakes, not just stored/async SB2 blobs.

## Why Paykit needs pubky-noise (not just pubky-crypto)

Paykit uses the **async outbox/inbox routing infrastructure**:
- ContextId-based directory structure for message discovery
- Contact polling patterns (recipients poll known contacts)
- Integration with homeserver storage for request/response flow

## Why extract pubky-crypto anyway?

1. **Cleaner layering** inside pubky-noise (crypto separated from session/routing)
2. **Smaller dependency for future pure-crypto-only consumers**
3. **Clear security boundary** (primitives in one focused, auditable crate)
4. **Testability** (crypto can be tested without network concerns)

## Phase 1 - Paykit naming + API cleanup (breaking)

- AuthenticatedTransport -> HomeserverSessionStorage
- UnauthenticatedTransportRead -> HomeserverPublicStorageRead
- SUPPORTED_SNAPSHOT_PATH -> SUPPORTED_METHODS_INDEX_PATH
- Unify get_payment_list() vs get_supported_snapshot() into single API

## Phase 2 - Extract primitives into pubky-crypto

Move from pubky-noise:
- errors.rs core types (CryptoError enum)
- sealed_blob.rs v1 helpers (x25519_generate_keypair, encrypt/decrypt)
- sealed_blob_v2.rs SB2 encode/decode, AAD computation
- ukd.rs UKD primitives (issue_app_cert, sign_typed_content, etc)
- kdf.rs derivation helpers
- secure_mem.rs mlock protection (feature-gated)

Update pubky-noise to depend on and re-export pubky-crypto.

## Phase 3 - Update pubky-ring bridges

- Verify bridges work via pubky-noise re-exports
- Move computeInboxKid into pubky-crypto as derive_inbox_kid
- Rebuild native libs and update bundled binaries

## Phase 4 - Reduce Paykit/Atomicity redundancy

- Update Atomicity Specification.md trait names
- Move shared async-messaging primitives to pubky-crypto

## Verification

| Repo | Check |
|------|-------|
| pubky-crypto | cargo test, cargo clippy |
| pubky-noise | cargo test, all feature sets |
| paykit-rs | cargo test, demos compile |
| paykit-mobile | UniFFI bindings, Kotlin/Swift build |
| pubky-ring | TS typecheck, Android/iOS build |
