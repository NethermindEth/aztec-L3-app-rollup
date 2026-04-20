// Note-discovery log constants. Mirrors aztec-packages v4.2.0-nightly.20260408.
//
// Source paths inside the pinned upstream tag:
//   noir-projects/noir-protocol-circuits/crates/types/src/constants.nr
//   noir-projects/aztec-nr/aztec/src/messages/encoding.nr
//
// Phase 1 is scoped to the ONCHAIN_UNCONSTRAINED delivery mode (tag + ciphertext
// computed off-circuit in TypeScript, no in-circuit crypto). These constants
// describe only the log shape that the circuit passes through as public-input
// data -- they must match the upstream values exactly so recipient wallets built
// on `@aztec/stdlib` can decrypt L3 logs without reconfiguration.

// ---- Log shape (constants.nr upstream) ----

/// Size of one on-chain private log in fields: 1 tag + 15 ciphertext fields.
pub global PRIVATE_LOG_SIZE_IN_FIELDS: u32 = 16;
/// Number of ciphertext fields (PRIVATE_LOG_SIZE_IN_FIELDS - 1 for the tag).
pub global PRIVATE_LOG_CIPHERTEXT_LEN: u32 = 15;

// ---- Plaintext shape (messages/encoding.nr upstream) ----

/// Length of the AES-128-CBC header ciphertext in bytes (2B length + PKCS#7 pad).
pub global HEADER_CIPHERTEXT_SIZE_IN_BYTES: u32 = 16;
/// AES PKCS#7 always adds at least one byte; since the body is a multiple of 16,
/// a full 16-byte padding block is always appended.
pub global AES128_PKCS7_EXPANSION_IN_BYTES: u32 = 16;
/// Fields reserved at the head of the ciphertext for the ephemeral pk x-coord.
pub global EPH_PK_X_SIZE_IN_FIELDS: u32 = 1;
/// Plaintext byte budget: (15 - 1) * 31 - 16 - 16 = 402.
pub global MESSAGE_PLAINTEXT_SIZE_IN_BYTES: u32 =
    (PRIVATE_LOG_CIPHERTEXT_LEN - EPH_PK_X_SIZE_IN_FIELDS) * 31
        - HEADER_CIPHERTEXT_SIZE_IN_BYTES
        - AES128_PKCS7_EXPANSION_IN_BYTES;
/// Plaintext field budget: 402 / 32 = 12 (fields are serialized at 32 B/field).
pub global MESSAGE_PLAINTEXT_LEN: u32 = MESSAGE_PLAINTEXT_SIZE_IN_BYTES / 32;
/// Expanded metadata is a single field packing (u64 msg_type_id | u64 msg_metadata).
pub global MESSAGE_EXPANDED_METADATA_LEN: u32 = 1;
/// Maximum content fields after the expanded-metadata prefix.
pub global MAX_MESSAGE_CONTENT_LEN: u32 = MESSAGE_PLAINTEXT_LEN - MESSAGE_EXPANDED_METADATA_LEN;

// ---- Domain separators (copied verbatim from upstream constants.nr) ----
// These are the only separators the L3 ever references; the rest are irrelevant.

pub global DOM_SEP__UNCONSTRAINED_MSG_LOG_TAG: u32 = 1485357192;
pub global DOM_SEP__PRIVATE_LOG_FIRST_FIELD: u32 = 2769976252;
pub global DOM_SEP__APP_SILOED_ECDH_SHARED_SECRET: u32 = 1707851664;
pub global DOM_SEP__ECDH_SUBKEY: u32 = 4277646631;
pub global DOM_SEP__ECDH_FIELD_MASK: u32 = 190532684;
pub global DOM_SEP__CONTRACT_ADDRESS_V1: u32 = 1788365517;
pub global DOM_SEP__PUBLIC_KEYS_HASH: u32 = 777457226;
pub global DOM_SEP__NHK_M: u32 = 242137788;
pub global DOM_SEP__IVSK_M: u32 = 2747825907;
pub global DOM_SEP__OVSK_M: u32 = 4272201051;
pub global DOM_SEP__TSK_M: u32 = 1546190975;

// ---- L3 message-type namespace ----
//
// Aztec reserves msg_type_id values 0..255 for its own protocol messages
// (noir-projects/aztec-nr/aztec/src/messages/msg_type.nr). To avoid collision if
// L3 users share a PXE with Aztec accounts, L3 message types start at 0x100.

pub global L3_MSG_TYPE_NOTE: u64 = 0x100;
