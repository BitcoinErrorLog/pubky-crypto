# Pubky Stack Finalization Plan (v2)

Comprehensive plan to finalize the spec, extract `pubky-crypto`, clean up `pubky-noise`, and propagate changes through all downstream repos. Incorporates all of Antoine's review feedback plus gaps identified in review.

> [!IMPORTANT]
> This plan results in: **finalized PUBKY_CRYPTO_SPEC**, **finalized pubky-noise**, **scaffolded pubky-crypto**, and **updated paykit-rs, atomicity-core, atomicity-research, pubky-ring, bitkit-android, bitkit-ios, pubky-knowledge-base**.

---

## Repos Affected

| Repo | Impact |
|------|--------|
| [pubky-core](file:///Users/john/vibes-dev/pubky-core) | Spec updates (PUBKY_CRYPTO_SPEC.md) |
| [pubky-crypto](file:///Users/john/vibes-dev/pubky-crypto) | **New crate** — scaffold + receive modules |
| [pubky-noise](file:///Users/john/vibes-dev/pubky-noise) | Module extraction, re-exports, Cargo.toml |
| [paykit-rs](file:///Users/john/vibes-dev/paykit-rs) | Breaking renames + import migration (6 sub-crates) |
| [atomicity-core](file:///Users/john/vibes-dev/atomicity-core) | Comment updates referencing pubky-noise |
| [atomicity-research](file:///Users/john/vibes-dev/atomicity-research) | Rename `AtomicityAuthenticatedTransport` in spec |
| [pubky-ring](file:///Users/john/vibes-dev/pubky-ring) | Rebuild native libs, verify bridges |
| [bitkit-android](file:///Users/john/vibes-dev/bitkit-android) | Regenerate UniFFI, update renamed refs |
| [bitkit-ios](file:///Users/john/vibes-dev/bitkit-ios) | Regenerate UniFFI, replace xcframework |
| [pubky-knowledge-base](file:///Users/john/vibes-dev/pubky-knowledge-base) | Update stale docs (Paykit.md, Pubky Noise.md, Pubky Ring.md) |

---

## Phase 0: Knowledge Base Updates

The knowledge base docs are stale and will become more so after our changes. Update now to establish correct baseline, then update again after code changes.

#### [MODIFY] [Pubky Noise.md](file:///Users/john/vibes-dev/pubky-knowledge-base/Explore/Technologies/Pubky%20Noise.md)

- Add XX (TOFU) pattern alongside IK — docs currently only describe IK
- Add Sealed Blob v2 binary wire format details (currently only JSON format)
- Add pubky-crypto as the new primitives crate
- Update key derivation section to reference HKDF-SHA512 (currently says HKDF-SHA256)
- Add async stored delivery mode (currently only mentions live transport)

#### [MODIFY] [Paykit.md](file:///Users/john/vibes-dev/pubky-knowledge-base/Explore/Technologies/Paykit.md)

- Update AAD format from `paykit:v0:{purpose}:...` to spec-compliant `pubky-envelope/v2:...`
- Rename "snapshot" references to "supported methods index"
- Note the relationship to Atomicity protocol more explicitly

#### [MODIFY] [Pubky Ring.md](file:///Users/john/vibes-dev/pubky-knowledge-base/Explore/Technologies/Pubky%20Ring.md)

- Update key derivation from `HKDF-SHA256 with context "pubky-noise-v1"` to actual spec: `HKDF-SHA512 with salt "pubky-noise-x25519:v1"` per [kdf.rs](file:///Users/john/vibes-dev/pubky-noise/src/kdf.rs)
- Add Ring Transport Abstraction concept (after §13 is written)

---

## Phase 1: Spec Finalization (PUBKY_CRYPTO_SPEC.md)

#### [MODIFY] [PUBKY_CRYPTO_SPEC.md](file:///Users/john/vibes-dev/pubky-core/docs/PUBKY_CRYPTO_SPEC.md)

Current sections: §1-12 + Appendices A-E

**1.1 — Add §7.7.1: Traffic Analysis Note** (within §7 Async Messaging)

- `context_id` in storage paths leaks communication metadata
- MVP: one inbox/outbox == one contextId (simpler polling)
- Future: single-inbox model where contextId is only inside encrypted envelope

**1.2 — Update §11: Security Considerations**

- Add "data remanence" argument for module extraction (Antoine)
- Add rate-limit requirement for Ring interface calls (prevent memory exhaustion attack — BIP32 prefix precedent)
- Add note on not exposing unbounded Ring API calls

**1.3 — Update §12: Implementation Reference**

- Add `pubky-crypto` crate to dependency tree diagram
- Update: `Ring → pubky-noise → pubky-crypto`, `Paykit → pubky-noise → pubky-crypto`

**1.4 — Add §13: Ring Transport Abstraction**

The Ring-to-App communication interface (identified by Antoine as missing):

- Transport-agnostic interface (bytes-in/bytes-out, C-compatible)
- Current MVP: Relay + deep links ([AUTH.md](file:///Users/john/vibes-dev/pubky-core/docs/AUTH.md))
- Deployment topologies: same-device, cross-device (relay), cross-device (USB/BLE — future)
- Open question: whether Ring↔Bitkit same-user cross-device uses Noise (deferred)

**1.5 — Add §14: Transport Architecture**

Document Antoine's analysis with normative MVP pick:

| Model | Description | MVP? |
|-------|-------------|------|
| auth_server + stored blobs | Homeserver auth → SB2 delivery | ✅ **Normative** |
| Direct P2P noise | No homeserver | ❌ (mobile IP issues) |
| noise-then-auth-then-noise | Full encryption with homeserver | ❌ Long-term ideal |

**1.6 — Add §12.2: Connection State Machine (non-normative)**

Antoine's proposed shared-channel architecture as future target:

```
Subscribers (Paykit, Atomicity)
─────────────────────────────
Connection State Machine (ack, ordering, reconnection)
─────────────────────────────
Noise Stack (single channel per PKARR pubkey)
```

---

## Phase 2: Naming & API Cleanup (Breaking)

Atomic rename across paykit-rs, atomicity-research, and docs.

### paykit-rs renames

| Old Name | New Name | Files Affected |
|----------|----------|----------------|
| `AuthenticatedTransport` | `HomeserverSessionStorage` | ~26 refs across paykit-lib |
| `UnauthenticatedTransportRead` | `HomeserverPublicStorageRead` | ~8 refs |
| `PubkyAuthenticatedTransport` | `PubkyHomeserverSessionStorage` | 5 refs |
| `SUPPORTED_SNAPSHOT_PATH` | `SUPPORTED_METHODS_INDEX_PATH` | 4 refs |

Files requiring changes in paykit-rs:

| File | Action |
|------|--------|
| [transport/traits.rs](file:///Users/john/vibes-dev/paykit-rs/paykit-lib/src/transport/traits.rs) | Rename trait definitions |
| [transport/pubky/authenticated_transport.rs](file:///Users/john/vibes-dev/paykit-rs/paykit-lib/src/transport/pubky/authenticated_transport.rs) | Rename struct + **rename file** to `homeserver_session_storage.rs` |
| [transport/mod.rs](file:///Users/john/vibes-dev/paykit-rs/paykit-lib/src/transport/mod.rs) | Update re-exports |
| [lib.rs](file:///Users/john/vibes-dev/paykit-rs/paykit-lib/src/lib.rs) | Rename constant + update bounds |
| [prelude.rs](file:///Users/john/vibes-dev/paykit-rs/paykit-lib/src/prelude.rs) | Update re-exports |
| [rotation/manager.rs](file:///Users/john/vibes-dev/paykit-rs/paykit-lib/src/rotation/manager.rs) | Update imports + bounds |
| All paykit-interactive, paykit-subscriptions, paykit-demo-* | Grep and fix any references |

### Atomicity renames

| File | Change |
|------|--------|
| [Atomicity Specification.md:640](file:///Users/john/vibes-dev/atomicity-research/Atomicity%20Specification.md#L640) | `AtomicityAuthenticatedTransport` → `AtomicityHomeserverSessionStorage` |
| [atomicity-core/src/aad.rs](file:///Users/john/vibes-dev/atomicity-core/src/aad.rs) | Update doc comments referencing pubky-noise |
| [atomicity-core/src/lib.rs](file:///Users/john/vibes-dev/atomicity-core/src/lib.rs) | Update doc comment |

### Version bump strategy

- `paykit-lib`: **major version bump** (breaking public API)
- `pubky-noise`: **minor version bump** (internal restructuring, public API preserved via re-exports)
- `pubky-crypto`: starts at **0.1.0**

### Verification

```bash
cd ~/vibes-dev/paykit-rs && cargo test --all --all-features
grep -r "AuthenticatedTransport\|SUPPORTED_SNAPSHOT" --include="*.rs" .  # Zero matches
```

---

## Phase 3: Scaffold pubky-crypto + Extract Modules

> [!IMPORTANT]
> Phases 3 and 4 are executed as one **atomic unit** — you can't compile pubky-noise between extracting modules and adding re-exports.

#### [NEW] [pubky-crypto/Cargo.toml](file:///Users/john/vibes-dev/pubky-crypto/Cargo.toml)

```toml
[package]
name = "pubky-crypto"
version = "0.1.0"
edition = "2021"
description = "Pure cryptographic primitives for the Pubky ecosystem: SB2, UKD, KDF, X25519/Ed25519 helpers"

[features]
default = []
secure-mem = ["region"]

[dependencies]
x25519-dalek = "2"
ed25519-dalek = "2"
curve25519-dalek = "4"
sha2 = "0.10"
hkdf = "0.12"
chacha20poly1305 = "0.10"
blake3 = "1.5"
base64 = "0.22"
rand = "0.8"
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
serde_json = "1"
zeroize = "1"
thiserror = "1"
hex = "0.4"
region = { version = "3", optional = true }
```

#### Modules to move (with tests)

| Module | Lines | What moves | Tests |
|--------|-------|------------|-------|
| `errors.rs` | 234 | **Split**: `CryptoError` (crypto-only variants) into pubky-crypto. `NoiseError` stays in pubky-noise with `From<CryptoError>` | Split test assertions accordingly |
| `kdf.rs` | 105 | All 4 functions + constants | Inline tests move with module |
| `sealed_blob.rs` | 1034 | x25519 helpers, AEAD, SB envelope, `compute_kid`, AAD builders | All `#[cfg(test)]` blocks move |
| `sealed_blob_v2.rs` | 1240 | `Sb2Header`, CBOR reader/writer, `Sb2`, AAD/sig helpers | All tests move |
| `ukd.rs` | 1264 | `AppCert`, `KeyBinding`, typed signing, CBOR encoders | All tests move |
| `secure_mem.rs` | 216 | `LockedBytes`, mlock helpers (feature-gated) | All tests move |
| **ed25519 helpers** | ~30 | `ed25519_sign`, `ed25519_verify` from `identity_payload.rs` | Move to pubky-crypto (pure crypto, no transport) |

> **NOT moved** (per Antoine): async-messaging routing (storage_queue, handshake_queue, session_manager, transport, mobile_manager, streaming, datalink_adapter, client, server). These stay in pubky-noise.

#### Error type split details

```rust
// pubky-crypto/src/errors.rs
pub enum CryptoError {
    KeyDerivation(String),    // was NoiseError::Ring for KDF failures
    Serde(String),            // CBOR/JSON
    InvalidPeerKey,           // Low-order X25519
    Decryption(String),       // AEAD failures
    InvalidSignature,         // Ed25519 verify
    Other(String),
}

// pubky-noise keeps NoiseError, adds:
impl From<CryptoError> for NoiseError { ... }
```

---

## Phase 4: Update pubky-noise (atomic with Phase 3)

#### [MODIFY] [pubky-noise/Cargo.toml](file:///Users/john/vibes-dev/pubky-noise/Cargo.toml)

- Add: `pubky-crypto = { path = "../pubky-crypto" }`

#### [MODIFY] [pubky-noise/src/lib.rs](file:///Users/john/vibes-dev/pubky-noise/src/lib.rs)

Replace moved module declarations with re-exports **preserving all current public API symbols**:

```rust
// Re-export pubky-crypto modules (backward-compatible)
pub use pubky_crypto::kdf;
pub use pubky_crypto::sealed_blob;
pub use pubky_crypto::sealed_blob_v2;
pub use pubky_crypto::ukd;
#[cfg(feature = "secure-mem")]
pub use pubky_crypto::secure_mem;

// Re-export all previously-public symbols at crate root
pub use pubky_crypto::sealed_blob::{
    sealed_blob_encrypt, sealed_blob_decrypt,
    x25519_generate_keypair, x25519_public_from_secret, /* etc */
};
pub use pubky_crypto::sealed_blob_v2::{Sb2, Sb2Header, /* etc */};
pub use pubky_crypto::ukd::{issue_app_cert, verify_app_cert, /* etc */};
pub use pubky_crypto::{ed25519_sign, ed25519_verify};
```

#### Internal import updates

Files in pubky-noise that referenced `crate::kdf`, `crate::sealed_blob`, etc. need updating to either `pubky_crypto::` or through re-exports. Key files:

- `client.rs`, `server.rs` (kdf, errors)
- `identity_payload.rs` (ed25519 helpers → now in pubky-crypto)
- `ring.rs` (errors)
- `ffi/` (UniFFI macros must expose pubky-crypto types)
- `mobile_manager.rs` (sealed_blob)

#### Verification (Phase 3+4 together)

```bash
cd ~/vibes-dev/pubky-crypto && cargo test
cd ~/vibes-dev/pubky-noise && cargo test --all-features
```

---

## Phase 5: Update paykit-rs Imports

paykit-rs currently imports crypto primitives from `pubky_noise`. Re-exports mean nothing breaks, but for clean layering we point directly to `pubky_crypto`.

#### Cargo.toml changes

| Crate | pubky-crypto | pubky-noise |
|-------|-------------|-------------|
| paykit-lib | **Add** | Keep (for Noise transport types) |
| paykit-subscriptions | **Add** | Keep |
| paykit-interactive | Optional | **Keep** (uses NoiseClient) |
| paykit-demo-cli | Optional | **Keep** (uses NoiseClient/Server) |

#### Key import migrations

| File | `pubky_noise::X` → `pubky_crypto::X` |
|------|---------------------------------------|
| [protocol/sb2.rs](file:///Users/john/vibes-dev/paykit-rs/paykit-lib/src/protocol/sb2.rs) | `Sb2Header`, `Sb2`, `sb2_build_aad`, `sb2_compute_sig_input`, `ed25519_sign`, `ed25519_verify` |
| [keys.rs](file:///Users/john/vibes-dev/paykit-rs/paykit-lib/src/keys.rs) | `ukd::*`, `x25519_generate_keypair`, `x25519_public_from_secret`, `Sb2Header::compute_inbox_kid` |

#### Subscription nonces (Antoine Theme 7)

> [!WARNING]
> Antoine identified that paykit-subscriptions has its own nonce cache that would be lost on crash. Nonces should be **derivable from Ring root secret**.

- Review `paykit-subscriptions` nonce management
- If standalone random nonces: convert to HKDF-derived nonces from seed + counter
- Add crash recovery design: derive state from seed rather than caching independently
- This may require a new KDF function in pubky-crypto

#### Verification

```bash
cd ~/vibes-dev/paykit-rs && cargo test --all --all-features
grep -r "pubky_noise::sealed_blob\|pubky_noise::ukd\|pubky_noise::kdf" --include="*.rs" paykit-lib/src/  # Zero matches
```

---

## Phase 6: Update pubky-ring

#### Native lib rebuild

```bash
cd ~/vibes-dev/pubky-noise
./build-android.sh  # .so for Ring Android
./build-ios.sh      # .xcframework for Ring iOS
```

#### Verify bridges

- [PubkyNoiseModule.ts](file:///Users/john/vibes-dev/pubky-ring/src/utils/PubkyNoiseModule.ts) — no code changes needed (calls native module, not direct Rust imports)
- [paykitConnectAction.ts](file:///Users/john/vibes-dev/pubky-ring/src/utils/actions/paykitConnectAction.ts) — verify `computeInboxKid` call chain works
- TypeScript compile: `cd ~/vibes-dev/pubky-ring && npx tsc --noEmit`

---

## Phase 7: Update Bitkit Apps

#### bitkit-android

| File | Action |
|------|--------|
| [pubky_noise.kt](file:///Users/john/vibes-dev/bitkit-android/app/src/main/java/com/pubky/noise/pubky_noise.kt) | **Regenerate** (UniFFI) |
| [paykit_mobile.kt](file:///Users/john/vibes-dev/bitkit-android/app/src/main/java/uniffi/paykit_mobile/paykit_mobile.kt) | **Regenerate** (UniFFI) |
| Kotlin service files (6 files) | Verify compilation, update any `SUPPORTED_SNAPSHOT` references |
| Test files (2 files) | Verify compilation |

```bash
export JAVA_HOME="/opt/homebrew/opt/openjdk@21"
cd ~/vibes-dev/bitkit-android && ./gradlew compileDevDebugKotlin && ./gradlew testDevDebugUnitTest
```

#### bitkit-ios

| File | Action |
|------|--------|
| [PubkyNoise.swift](file:///Users/john/vibes-dev/bitkit-ios/Bitkit/PaykitIntegration/FFI/PubkyNoise.swift) | **Regenerate** |
| [PaykitMobile.swift](file:///Users/john/vibes-dev/bitkit-ios/Bitkit/PaykitIntegration/FFI/PaykitMobile.swift) | **Regenerate** |
| [PubkyNoise.xcframework](file:///Users/john/vibes-dev/bitkit-ios/Bitkit/PaykitIntegration/Frameworks/PubkyNoise.xcframework) | **Replace** |
| Swift service files (3 files) | Verify compilation |

---

## Phase 8: Documentation Updates

| Document | Updates |
|----------|---------|
| [IMPLEMENTATION_PLAN.md](file:///Users/john/vibes-dev/pubky-crypto/IMPLEMENTATION_PLAN.md) | Correct Phase 4: async-messaging stays OUT of pubky-crypto |
| [BITKIT_PAYKIT_INTEGRATION_MASTERGUIDE.md](file:///Users/john/vibes-dev/paykit-rs/BITKIT_PAYKIT_INTEGRATION_MASTERGUIDE.md) | All renamed APIs |
| [PAYKIT_INTEGRATION.md](file:///Users/john/vibes-dev/bitkit-android/PAYKIT_INTEGRATION.md) | All renamed APIs |
| [Pubky Noise.md](file:///Users/john/vibes-dev/pubky-knowledge-base/Explore/Technologies/Pubky%20Noise.md) | Add XX pattern, pubky-crypto, stored delivery |
| [Paykit.md](file:///Users/john/vibes-dev/pubky-knowledge-base/Explore/Technologies/Paykit.md) | Fix AAD format, rename snapshot, add Atomicity link |
| [Pubky Ring.md](file:///Users/john/vibes-dev/pubky-knowledge-base/Explore/Technologies/Pubky%20Ring.md) | Fix KDF details, add Ring Transport Abstraction |
| [Atomicity Specification.md](file:///Users/john/vibes-dev/atomicity-research/Atomicity%20Specification.md) | Rename `AtomicityAuthenticatedTransport` |

---

## Cross-Cutting Concerns

### ContextId Ownership

Antoine said "all what is ContextId shouldn't be in paykit." Currently in [paykit-lib/src/protocol/scope.rs](file:///Users/john/vibes-dev/paykit-rs/paykit-lib/src/protocol/scope.rs).

**Decision**: keep `context_id` in paykit for now. Rationale:
- ContextId generation involves `generate_context_id()` (random) and legacy `pair_context_id()` (SHA256 of sorted pubkeys)
- These are application-level identifiers, not pure crypto primitives
- Move to pubky-crypto later when the namespace spec stabilizes
- Tag in spec as "may move in future revision"

### `rate_limit.rs` / `metrics.rs` Extraction

Antoine noted these in paykit-interactive could be shared. **Decision**: defer to post-MVP. No code change now, but note in Phase 8 docs as planned future work.

### UniFFI Schema Updates

If paykit-lib's public API changes (renamed traits), `paykit-mobile/src/lib.rs` may need manual edits to the UniFFI-exposed functions. This is **not just a regeneration** — verify the exported function signatures don't reference old names.

---

## Execution Order

```mermaid
flowchart LR
    P0["Phase 0\nKnowledge Base"] --> P1["Phase 1\nSpec Updates"]
    P1 --> P2["Phase 2\nNaming Cleanup"]
    P2 --> P34["Phase 3+4\nExtract pubky-crypto\n+ Update pubky-noise"]
    P34 --> P5["Phase 5\nUpdate paykit-rs"]
    P5 --> P6["Phase 6\nRebuild pubky-ring"]
    P6 --> P7["Phase 7\nUpdate Bitkit apps"]
    P7 --> P8["Phase 8\nUpdate docs"]
```

**Each phase gate**: tests must pass (where applicable) before proceeding.

---

## Completion Status

| Phase | Status | Verified |
|-------|--------|----------|
| Phase 0: Knowledge Base Updates | ✅ Complete | Pubky Noise.md, Paykit.md, Pubky Ring.md updated |
| Phase 1: Spec Finalization | ✅ Complete | §7.7.3, §11.7-11.8, §12.3-12.5, §13, §14 added; TOC + Appendix C updated |
| Phase 2: Naming & API Cleanup | ✅ Complete | All renames applied; paykit-lib 2.0.0; atomicity-research updated |
| Phase 3+4: pubky-crypto + pubky-noise | ✅ Complete | pubky-crypto 0.1.0 with 8 modules, 32 tests; pubky-noise re-exports, 162 tests |
| Phase 5: paykit-rs Imports | ✅ Complete | All 8 workspace crates migrated; cargo test --all --all-features passes |
| Phase 6: Update pubky-ring | ✅ Complete | Android .so + Kotlin, iOS xcframework + Swift rebuilt; TS compiles; 178 Jest tests pass |
| Phase 7: Update Bitkit Apps | ✅ Complete | Android: 663 tests pass; iOS: BUILD SUCCEEDED, no crypto-related failures |
| Phase 8: Documentation Updates | ✅ Complete | All docs updated with pubky-crypto references |

### Cross-Cutting Concerns Resolution

| Concern | Resolution |
|---------|------------|
| ContextId ownership | Kept in paykit-lib per decision; tagged "may move in future revision" in spec |
| rate_limit.rs / metrics.rs extraction | Deferred to post-MVP; noted in MASTERGUIDE |
| UniFFI schema updates | Verified: zero old names in paykit-mobile/src/lib.rs; FFI types (AuthenticatedTransportFFI) remain as FFI-layer names, distinct from renamed traits |
| async-messaging in pubky-crypto | Confirmed NOT moved: storage_queue, handshake_queue, session_manager, transport, mobile_manager, streaming, datalink_adapter, client, server all stay in pubky-noise |
