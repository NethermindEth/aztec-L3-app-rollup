//! Note-discovery message layer for the L3.
//!
//! Scope: Phase 1 scaffold for the ONCHAIN_UNCONSTRAINED delivery model that
//! matches aztec-packages v4.2.0-nightly.20260408 production mode. All tag and
//! ciphertext construction lives off-circuit in the TypeScript wallet (see
//! `tests/src/messages/`); this crate only provides the constants and the
//! `PrivateLog` pass-through struct consumed by later phases' circuits.
//!
//! Phase 2 will thread `PrivateLog` values through `payment`, `deposit`, and the
//! aggregation tree as public-input data. Phase 3 will emit them from the L2
//! settlement contracts. Phase 4 will add the wallet/indexer that produces and
//! decrypts them.

pub mod constants;
pub mod log;
