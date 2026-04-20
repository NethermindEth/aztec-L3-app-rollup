/**
 * Recursive-path shape constants and boundary assertions.
 *
 * These are the sizes the L3RecursiveSettlement contract ABI commits to.
 * They are protocol / contract invariants, not tunable project config --
 * hence the assertion-oriented form (throw if not exact) rather than a
 * config dial.
 *
 * Batch sizing (MAX_BATCH_SIZE etc.) lives in state.ts because it's used
 * by state tracking; this file is specifically the submission boundary --
 * the seam where client bytes cross into the contract call and any shape
 * mismatch would have historically been silently truncated by the SDK
 * (see SILENT_FAILURE_REVIEW.md).
 *
 * Mirror of:
 *   contract_recursive/src/main.nr  (BATCH_OUTPUT_FIELDS, BATCH_16_*, BATCH_64_*)
 *   circuits/wrapper/src/main.nr    (UltraHonkZKProof / VK field counts)
 */

// UltraHonkZK (noir-recursive target) proof / VK widths. Fixed by the bb
// protocol -- not tunable. If bb ever changes these, this file is the one
// place to update and every submit-boundary caller re-asserts.
export const UH_PROOF_FIELDS = 500;
export const UH_VK_FIELDS = 115;

// BatchOutput public-input layout (10 fields: old/new state root, 4 batch
// commitment hashes, private_logs_hash, 2 tree start indices, and
// per_tx_vk_hashes_commit). Matches BATCH_OUTPUT_FIELDS in
// contract_recursive/src/main.nr. This is the public-input width for
// submit_batch (the 8-slot wrapper path).
export const BATCH_OUTPUT_FIELDS = 10;

// Aggregator public-input widths. Each level appends inner VK-hash fields
// that the contract asserts against its committed immutables, closing the
// inner-VK substitution gap at every level. per_tx_vk_hashes_commit rides
// through unchanged at every level (BatchOutput index 9).
//   - submit_batch_16: 9 merged BatchOutput + wrapper_vk_hash + per_tx_commit = 11
//   - submit_batch_64: 9 merged BatchOutput + 3 VK hashes + per_tx_commit = 13
export const PUB_COUNT_16 = 11;
export const PUB_COUNT_64 = 13;

// Per-tx encrypted-log payload dimensions (Phase 2 note discovery):
// MAX_OUTPUTS_PER_TX * PRIVATE_LOG_SIZE_IN_FIELDS = 2 * 16 = 32 fields per tx.
// Batch-level counts below.
export const TX_LOG_PAYLOAD_LEN = 32;
export const BATCH_LOGS_FLAT_COUNT = 256;       // 8 tx * 32 fields
export const BATCH_16_LOGS_FLAT_COUNT = 512;    // 16 tx * 32
export const BATCH_64_LOGS_FLAT_COUNT = 2048;   // 64 tx * 32

// 16-slot aggregated batch (wrapper_16). Mirrors BATCH_16_* globals in
// contract_recursive/src/main.nr.
export const BATCH_16_SIZE = 16;
export const BATCH_16_NULLIFIERS_COUNT = 32;
export const BATCH_16_NOTE_HASHES_COUNT = 32;

// Intermediate wrapper_32 (32-slot doubly-merged) sizing. Consumed only
// by wrapper_64; not exposed to the contract.
export const BATCH_32_SIZE = 32;
export const BATCH_32_NULLIFIERS_COUNT = 64;
export const BATCH_32_NOTE_HASHES_COUNT = 64;

// 64-slot aggregated batch (wrapper_64). Mirrors BATCH_64_* globals in
// contract_recursive/src/main.nr.
export const BATCH_64_SIZE = 64;
export const BATCH_64_NULLIFIERS_COUNT = 128;
export const BATCH_64_NOTE_HASHES_COUNT = 128;

// Assert that a recursive-path submit payload has the exact shapes the
// contract ABI expects. Throws with a clear message if any length is
// wrong; the original silent-truncation bug was specifically at this
// seam, so we re-arm it explicitly here.
export function assertRecursiveSubmitShape(
  label: string,
  proofFields: ArrayLike<unknown>,
  vkFields: ArrayLike<unknown>,
  publicInputs: ArrayLike<unknown>,
  nullifiers: ArrayLike<unknown>,
  noteHashes: ArrayLike<unknown>,
  depositNullifiers: ArrayLike<unknown>,
  withdrawalClaims: ArrayLike<unknown>,
  expectedPublicInputs: number,
  expectedNullifiers: number,
  expectedNoteHashes: number,
  expectedSettleSlots: number,
): void {
  const check = (got: number, want: number, what: string) => {
    if (got !== want) {
      throw new Error(`${label}: ${what} has ${got} fields (expected ${want})`);
    }
  };
  check(proofFields.length, UH_PROOF_FIELDS, "proof");
  check(vkFields.length, UH_VK_FIELDS, "vk");
  check(publicInputs.length, expectedPublicInputs, "public_inputs");
  check(nullifiers.length, expectedNullifiers, "nullifiers");
  check(noteHashes.length, expectedNoteHashes, "note_hashes");
  check(depositNullifiers.length, expectedSettleSlots, "deposit_nullifiers");
  check(withdrawalClaims.length, expectedSettleSlots, "withdrawal_claims");
}
