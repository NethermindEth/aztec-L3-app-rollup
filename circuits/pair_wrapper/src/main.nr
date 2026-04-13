// pair_wrapper -- recursive UltraHonk aggregator for 2 wrapper proofs.
//
// Verifies two wrapper proofs, re-feeds both batches' settle-data arrays so
// that their poseidon2 hashes can be cross-checked, chains the state roots and
// tree indices, and exposes merged batch=16-equivalent public inputs.
//
// The output proof is an UltraHonk proof that attests to one combined state
// transition from (A.old_state_root, A.null_start, A.nh_start) to
// (B.new_state_root, B.null_start + B.null_count, B.nh_start + B.nh_count).
//
// Emitted public inputs mirror the BatchOutput schema (8 fields), sized for
// the combined 16-tx merged batch.

use l3_types::poseidon2_hash;
use bb_proof_verification::{verify_honk_proof, UltraHonkVerificationKey, UltraHonkZKProof};

// These MUST match circuits/batch_app_standalone globals (batch=8):
global SUB_BATCH_SIZE: u32 = 8;
global SUB_BATCH_NULLIFIERS: u32 = 16;  // SUB_BATCH_SIZE * 2
global SUB_BATCH_NOTE_HASHES: u32 = 16; // SUB_BATCH_SIZE * 2

// Merged-batch array sizes (doubled):
global MERGED_BATCH_SIZE: u32 = 16;
global MERGED_BATCH_NULLIFIERS: u32 = 32;
global MERGED_BATCH_NOTE_HASHES: u32 = 32;

// Wrapper BatchOutput layout (shared between A and B wrapper proofs):
//   [0] old_state_root
//   [1] new_state_root
//   [2] nullifiers_batch_hash
//   [3] note_hashes_batch_hash
//   [4] deposit_nullifiers_hash
//   [5] withdrawal_claims_hash
//   [6] nullifier_tree_start_index
//   [7] note_hash_tree_start_index
global WRAPPER_PUB_COUNT: u32 = 8;

fn main(
    // --- private inputs ---
    // Shared wrapper VK (both sub-batches use the same wrapper circuit).
    wrapper_vk: UltraHonkVerificationKey,
    wrapper_vk_hash: Field,

    // Batch A wrapper proof + its public inputs.
    wrapper_proof_a: UltraHonkZKProof,
    wrapper_public_inputs_a: [Field; WRAPPER_PUB_COUNT],

    // Batch B wrapper proof + its public inputs.
    wrapper_proof_b: UltraHonkZKProof,
    wrapper_public_inputs_b: [Field; WRAPPER_PUB_COUNT],

    // Re-fed settle-data arrays so we can recompute combined hashes.
    nullifiers_a: [Field; SUB_BATCH_NULLIFIERS],
    note_hashes_a: [Field; SUB_BATCH_NOTE_HASHES],
    deposits_a: [Field; SUB_BATCH_SIZE],
    withdrawals_a: [Field; SUB_BATCH_SIZE],

    nullifiers_b: [Field; SUB_BATCH_NULLIFIERS],
    note_hashes_b: [Field; SUB_BATCH_NOTE_HASHES],
    deposits_b: [Field; SUB_BATCH_SIZE],
    withdrawals_b: [Field; SUB_BATCH_SIZE],

    // --- public outputs (batch=16 merged shape, mirrors BatchOutput) ---
    old_state_root: pub Field,
    new_state_root: pub Field,
    merged_nullifiers_hash: pub Field,
    merged_note_hashes_hash: pub Field,
    merged_deposit_nullifiers_hash: pub Field,
    merged_withdrawal_claims_hash: pub Field,
    nullifier_tree_start_index: pub Field,
    note_hash_tree_start_index: pub Field,
) {
    // 1. Verify both wrapper proofs against the shared VK.
    verify_honk_proof(wrapper_vk, wrapper_proof_a, wrapper_public_inputs_a, wrapper_vk_hash);
    verify_honk_proof(wrapper_vk, wrapper_proof_b, wrapper_public_inputs_b, wrapper_vk_hash);

    // 2. Re-fed arrays must match each wrapper's committed hashes.
    assert(
        poseidon2_hash(nullifiers_a) == wrapper_public_inputs_a[2],
        "pair: nullifiers_a hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes_a) == wrapper_public_inputs_a[3],
        "pair: note_hashes_a hash mismatch",
    );
    assert(
        poseidon2_hash(deposits_a) == wrapper_public_inputs_a[4],
        "pair: deposits_a hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawals_a) == wrapper_public_inputs_a[5],
        "pair: withdrawals_a hash mismatch",
    );

    assert(
        poseidon2_hash(nullifiers_b) == wrapper_public_inputs_b[2],
        "pair: nullifiers_b hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes_b) == wrapper_public_inputs_b[3],
        "pair: note_hashes_b hash mismatch",
    );
    assert(
        poseidon2_hash(deposits_b) == wrapper_public_inputs_b[4],
        "pair: deposits_b hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawals_b) == wrapper_public_inputs_b[5],
        "pair: withdrawals_b hash mismatch",
    );

    // 3. State-root chain: B's old root == A's new root.
    assert(
        wrapper_public_inputs_a[1] == wrapper_public_inputs_b[0],
        "pair: state root chain broken",
    );

    // 4. Tree-index chain: B's starting indices == A's starting indices + A's counts.
    let mut null_count_a: Field = 0;
    for i in 0..SUB_BATCH_NULLIFIERS {
        if nullifiers_a[i] != 0 { null_count_a += 1; }
    }
    let mut nh_count_a: Field = 0;
    for i in 0..SUB_BATCH_NOTE_HASHES {
        if note_hashes_a[i] != 0 { nh_count_a += 1; }
    }
    assert(
        wrapper_public_inputs_b[6] == wrapper_public_inputs_a[6] + null_count_a,
        "pair: nullifier tree index chain broken",
    );
    assert(
        wrapper_public_inputs_b[7] == wrapper_public_inputs_a[7] + nh_count_a,
        "pair: note hash tree index chain broken",
    );

    // 5. Build merged arrays and compute combined hashes.
    let mut merged_nullifiers: [Field; MERGED_BATCH_NULLIFIERS] = [0; MERGED_BATCH_NULLIFIERS];
    let mut merged_note_hashes: [Field; MERGED_BATCH_NOTE_HASHES] = [0; MERGED_BATCH_NOTE_HASHES];
    let mut merged_deposits: [Field; MERGED_BATCH_SIZE] = [0; MERGED_BATCH_SIZE];
    let mut merged_withdrawals: [Field; MERGED_BATCH_SIZE] = [0; MERGED_BATCH_SIZE];

    for i in 0..SUB_BATCH_NULLIFIERS {
        merged_nullifiers[i] = nullifiers_a[i];
        merged_nullifiers[SUB_BATCH_NULLIFIERS + i] = nullifiers_b[i];
    }
    for i in 0..SUB_BATCH_NOTE_HASHES {
        merged_note_hashes[i] = note_hashes_a[i];
        merged_note_hashes[SUB_BATCH_NOTE_HASHES + i] = note_hashes_b[i];
    }
    for i in 0..SUB_BATCH_SIZE {
        merged_deposits[i] = deposits_a[i];
        merged_deposits[SUB_BATCH_SIZE + i] = deposits_b[i];
        merged_withdrawals[i] = withdrawals_a[i];
        merged_withdrawals[SUB_BATCH_SIZE + i] = withdrawals_b[i];
    }

    // 6. Expose merged public outputs.
    assert(old_state_root == wrapper_public_inputs_a[0], "pair: old state root mismatch");
    assert(new_state_root == wrapper_public_inputs_b[1], "pair: new state root mismatch");
    assert(
        merged_nullifiers_hash == poseidon2_hash(merged_nullifiers),
        "pair: merged nullifiers hash mismatch",
    );
    assert(
        merged_note_hashes_hash == poseidon2_hash(merged_note_hashes),
        "pair: merged note hashes hash mismatch",
    );
    assert(
        merged_deposit_nullifiers_hash == poseidon2_hash(merged_deposits),
        "pair: merged deposit nullifiers hash mismatch",
    );
    assert(
        merged_withdrawal_claims_hash == poseidon2_hash(merged_withdrawals),
        "pair: merged withdrawal claims hash mismatch",
    );
    assert(
        nullifier_tree_start_index == wrapper_public_inputs_a[6],
        "pair: nullifier tree start index mismatch",
    );
    assert(
        note_hash_tree_start_index == wrapper_public_inputs_a[7],
        "pair: note hash tree start index mismatch",
    );
}
