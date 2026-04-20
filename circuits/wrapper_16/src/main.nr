// wrapper_16 -- recursive UltraHonk aggregator for 2 wrapper proofs.
//
// Level 1 of the aggregation tree. Consumed by submit_batch_16 directly for
// 16-slot L2 submission, or by wrapper_32 as the next aggregation level.
//
// Verifies two wrapper proofs, re-feeds both batches' settle-data arrays so
// that their poseidon2 hashes can be cross-checked, chains the state roots
// and tree indices, and exposes merged batch=16 public inputs.
//
// The output proof is an UltraHonk proof that attests to one combined state
// transition from (A.old_state_root, A.null_start, A.nh_start) to
// (B.new_state_root, B.null_start + B.null_count, B.nh_start + B.nh_count).

use l3_types::poseidon2_hash;
use bb_proof_verification::{verify_honk_proof, UltraHonkVerificationKey, UltraHonkZKProof};

// Inner wrapper sizes (MUST match circuits/batch_app_standalone globals):
global SUB_BATCH_SIZE: u32 = 8;
global SUB_BATCH_NULLIFIERS: u32 = 16;  // SUB_BATCH_SIZE * 2
global SUB_BATCH_NOTE_HASHES: u32 = 16; // SUB_BATCH_SIZE * 2
global SUB_BATCH_LOGS_FLAT: u32 = 256;  // SUB_BATCH_SIZE * TX_LOG_PAYLOAD_LEN

// Output (16-slot merged) array sizes:
global BATCH_16_SIZE: u32 = 16;
global BATCH_16_NULLIFIERS: u32 = 32;
global BATCH_16_NOTE_HASHES: u32 = 32;
global BATCH_16_LOGS_FLAT: u32 = 512;   // 2 * SUB_BATCH_LOGS_FLAT

// wrapper public-input layout (10 fields):
//   [0] old_state_root
//   [1] new_state_root
//   [2] nullifiers_batch_hash
//   [3] note_hashes_batch_hash
//   [4] deposit_nullifiers_hash
//   [5] withdrawal_claims_hash
//   [6] private_logs_hash
//   [7] nullifier_tree_start_index
//   [8] note_hash_tree_start_index
//   [9] per_tx_vk_hashes_commit  -- poseidon2 of the four per-tx VK hashes,
//                                    propagated unchanged through the tree.
global WRAPPER_PUB_COUNT: u32 = 10;

// wrapper_16 outputs 11 fields: 9 merged BatchOutput + out_wrapper_vk_hash
// (inner-VK substitution hardening; contract pins it) + per_tx_vk_hashes_commit
// (per-tx circuit binding; contract pins it).

fn main(
    // --- private inputs ---
    // Shared wrapper VK (both halves use the same wrapper circuit).
    wrapper_vk: UltraHonkVerificationKey,
    wrapper_vk_hash: Field,

    // Half A wrapper proof + its public inputs.
    wrapper_proof_a: UltraHonkZKProof,
    wrapper_public_inputs_a: [Field; WRAPPER_PUB_COUNT],

    // Half B wrapper proof + its public inputs.
    wrapper_proof_b: UltraHonkZKProof,
    wrapper_public_inputs_b: [Field; WRAPPER_PUB_COUNT],

    // Re-fed settle-data arrays so we can recompute combined hashes.
    nullifiers_a: [Field; SUB_BATCH_NULLIFIERS],
    note_hashes_a: [Field; SUB_BATCH_NOTE_HASHES],
    deposits_a: [Field; SUB_BATCH_SIZE],
    withdrawals_a: [Field; SUB_BATCH_SIZE],
    private_logs_a: [Field; SUB_BATCH_LOGS_FLAT],

    nullifiers_b: [Field; SUB_BATCH_NULLIFIERS],
    note_hashes_b: [Field; SUB_BATCH_NOTE_HASHES],
    deposits_b: [Field; SUB_BATCH_SIZE],
    withdrawals_b: [Field; SUB_BATCH_SIZE],
    private_logs_b: [Field; SUB_BATCH_LOGS_FLAT],

    // --- public outputs (16-slot merged shape + inner VK hash) ---
    old_state_root: pub Field,
    new_state_root: pub Field,
    merged_nullifiers_hash: pub Field,
    merged_note_hashes_hash: pub Field,
    merged_deposit_nullifiers_hash: pub Field,
    merged_withdrawal_claims_hash: pub Field,
    merged_private_logs_hash: pub Field,
    nullifier_tree_start_index: pub Field,
    note_hash_tree_start_index: pub Field,
    // Bound to contract's tube_vk_hash via submit_batch_16:
    out_wrapper_vk_hash: pub Field,
    // Bound to contract's per_tx_vk_hashes_commit via submit_batch_16:
    out_per_tx_vk_hashes_commit: pub Field,
) {
    // 1. Verify both wrapper proofs against the shared VK.
    verify_honk_proof(wrapper_vk, wrapper_proof_a, wrapper_public_inputs_a, wrapper_vk_hash);
    verify_honk_proof(wrapper_vk, wrapper_proof_b, wrapper_public_inputs_b, wrapper_vk_hash);

    // 2. Re-fed arrays must match each wrapper's committed hashes.
    assert(
        poseidon2_hash(nullifiers_a) == wrapper_public_inputs_a[2],
        "wrapper_16: nullifiers_a hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes_a) == wrapper_public_inputs_a[3],
        "wrapper_16: note_hashes_a hash mismatch",
    );
    assert(
        poseidon2_hash(deposits_a) == wrapper_public_inputs_a[4],
        "wrapper_16: deposits_a hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawals_a) == wrapper_public_inputs_a[5],
        "wrapper_16: withdrawals_a hash mismatch",
    );
    assert(
        poseidon2_hash(private_logs_a) == wrapper_public_inputs_a[6],
        "wrapper_16: private_logs_a hash mismatch",
    );

    assert(
        poseidon2_hash(nullifiers_b) == wrapper_public_inputs_b[2],
        "wrapper_16: nullifiers_b hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes_b) == wrapper_public_inputs_b[3],
        "wrapper_16: note_hashes_b hash mismatch",
    );
    assert(
        poseidon2_hash(deposits_b) == wrapper_public_inputs_b[4],
        "wrapper_16: deposits_b hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawals_b) == wrapper_public_inputs_b[5],
        "wrapper_16: withdrawals_b hash mismatch",
    );
    assert(
        poseidon2_hash(private_logs_b) == wrapper_public_inputs_b[6],
        "wrapper_16: private_logs_b hash mismatch",
    );

    // 3. State-root chain: B's old root == A's new root.
    assert(
        wrapper_public_inputs_a[1] == wrapper_public_inputs_b[0],
        "wrapper_16: state root chain broken",
    );

    // 4. Tree-index chain.
    let mut null_count_a: Field = 0;
    for i in 0..SUB_BATCH_NULLIFIERS {
        if nullifiers_a[i] != 0 { null_count_a += 1; }
    }
    let mut nh_count_a: Field = 0;
    for i in 0..SUB_BATCH_NOTE_HASHES {
        if note_hashes_a[i] != 0 { nh_count_a += 1; }
    }
    assert(
        wrapper_public_inputs_b[7] == wrapper_public_inputs_a[7] + null_count_a,
        "wrapper_16: nullifier tree index chain broken",
    );
    assert(
        wrapper_public_inputs_b[8] == wrapper_public_inputs_a[8] + nh_count_a,
        "wrapper_16: note hash tree index chain broken",
    );

    // 5. Build merged arrays and compute combined hashes.
    let mut merged_nullifiers: [Field; BATCH_16_NULLIFIERS] = [0; BATCH_16_NULLIFIERS];
    let mut merged_note_hashes: [Field; BATCH_16_NOTE_HASHES] = [0; BATCH_16_NOTE_HASHES];
    let mut merged_deposits: [Field; BATCH_16_SIZE] = [0; BATCH_16_SIZE];
    let mut merged_withdrawals: [Field; BATCH_16_SIZE] = [0; BATCH_16_SIZE];
    let mut merged_private_logs: [Field; BATCH_16_LOGS_FLAT] = [0; BATCH_16_LOGS_FLAT];

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
    for i in 0..SUB_BATCH_LOGS_FLAT {
        merged_private_logs[i] = private_logs_a[i];
        merged_private_logs[SUB_BATCH_LOGS_FLAT + i] = private_logs_b[i];
    }

    // 6. Expose merged public outputs.
    assert(old_state_root == wrapper_public_inputs_a[0], "wrapper_16: old state root mismatch");
    assert(new_state_root == wrapper_public_inputs_b[1], "wrapper_16: new state root mismatch");
    assert(
        merged_nullifiers_hash == poseidon2_hash(merged_nullifiers),
        "wrapper_16: merged nullifiers hash mismatch",
    );
    assert(
        merged_note_hashes_hash == poseidon2_hash(merged_note_hashes),
        "wrapper_16: merged note hashes hash mismatch",
    );
    assert(
        merged_deposit_nullifiers_hash == poseidon2_hash(merged_deposits),
        "wrapper_16: merged deposit nullifiers hash mismatch",
    );
    assert(
        merged_withdrawal_claims_hash == poseidon2_hash(merged_withdrawals),
        "wrapper_16: merged withdrawal claims hash mismatch",
    );
    assert(
        merged_private_logs_hash == poseidon2_hash(merged_private_logs),
        "wrapper_16: merged private logs hash mismatch",
    );
    assert(
        nullifier_tree_start_index == wrapper_public_inputs_a[7],
        "wrapper_16: nullifier tree start index mismatch",
    );
    assert(
        note_hash_tree_start_index == wrapper_public_inputs_a[8],
        "wrapper_16: note hash tree start index mismatch",
    );

    // 7. Expose the wrapper VK hash the two inner proofs were verified under.
    //    submit_batch_16 asserts this == committed tube_vk_hash.
    assert(
        out_wrapper_vk_hash == wrapper_vk_hash,
        "wrapper_16: out wrapper vk hash mismatch",
    );

    // 8. Per-tx VK hashes commit propagation.
    //    Both halves must agree on the commit (same per-tx circuits were used
    //    for both sub-batches). Forward unchanged; contract's submit_batch_16
    //    binds it to its committed per_tx_vk_hashes_commit storage slot.
    assert(
        wrapper_public_inputs_a[9] == wrapper_public_inputs_b[9],
        "wrapper_16: per_tx_vk_hashes_commit mismatch between halves",
    );
    assert(
        out_per_tx_vk_hashes_commit == wrapper_public_inputs_a[9],
        "wrapper_16: out per_tx_vk_hashes_commit mismatch",
    );
}
