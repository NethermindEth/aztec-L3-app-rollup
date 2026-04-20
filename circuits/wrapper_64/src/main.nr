// wrapper_64 -- recursive UltraHonk aggregator for 2 wrapper_32 proofs.
//
// Top (level 3) of the aggregation tree for the 64-slot path. Consumed by
// submit_batch_64 directly. Verifies two wrapper_32 proofs, re-feeds their
// merged settle arrays, chains state roots + tree indices, and exposes the
// 64-slot BatchOutput plus the full inner VK-hash chain.

use l3_types::poseidon2_hash;
use bb_proof_verification::{verify_honk_proof, UltraHonkVerificationKey, UltraHonkZKProof};

// Inner wrapper_32 sizes:
global INNER_BATCH_SIZE: u32 = 32;
global INNER_NULLIFIERS: u32 = 64;
global INNER_NOTE_HASHES: u32 = 64;
global INNER_LOGS_FLAT: u32 = 1024; // 32 * TX_LOG_PAYLOAD_LEN

// Output (64-slot triply-merged) sizes:
global BATCH_64_SIZE: u32 = 64;
global BATCH_64_NULLIFIERS: u32 = 128;
global BATCH_64_NOTE_HASHES: u32 = 128;
global BATCH_64_LOGS_FLAT: u32 = 2048; // 2 * INNER_LOGS_FLAT

// Inner wrapper_32 public-input layout (12 fields):
//   [0..8]  BatchOutput (9 fields incl. private_logs_hash)
//   [9]     wrapper_vk_hash
//   [10]    w16_vk_hash
global INNER_PUB_COUNT: u32 = 11;

fn main(
    // --- private inputs ---
    // Shared wrapper_32 VK.
    w32_vk: UltraHonkVerificationKey,
    w32_vk_hash: Field,

    // Half A wrapper_32 proof + its public inputs.
    w32_proof_a: UltraHonkZKProof,
    w32_public_inputs_a: [Field; INNER_PUB_COUNT],

    // Half B wrapper_32 proof + its public inputs.
    w32_proof_b: UltraHonkZKProof,
    w32_public_inputs_b: [Field; INNER_PUB_COUNT],

    // Re-fed 32-slot-merged settle arrays from each half.
    nullifiers_a: [Field; INNER_NULLIFIERS],
    note_hashes_a: [Field; INNER_NOTE_HASHES],
    deposits_a: [Field; INNER_BATCH_SIZE],
    withdrawals_a: [Field; INNER_BATCH_SIZE],
    private_logs_a: [Field; INNER_LOGS_FLAT],

    nullifiers_b: [Field; INNER_NULLIFIERS],
    note_hashes_b: [Field; INNER_NOTE_HASHES],
    deposits_b: [Field; INNER_BATCH_SIZE],
    withdrawals_b: [Field; INNER_BATCH_SIZE],
    private_logs_b: [Field; INNER_LOGS_FLAT],

    // --- public outputs (64-slot triply-merged + 3 VK-chain fields) ---
    old_state_root: pub Field,
    new_state_root: pub Field,
    merged_nullifiers_hash: pub Field,
    merged_note_hashes_hash: pub Field,
    merged_deposit_nullifiers_hash: pub Field,
    merged_withdrawal_claims_hash: pub Field,
    merged_private_logs_hash: pub Field,
    nullifier_tree_start_index: pub Field,
    note_hash_tree_start_index: pub Field,
    // Full VK chain, all bound by contract's submit_batch_64:
    out_wrapper_vk_hash: pub Field,
    out_w16_vk_hash: pub Field,
    out_w32_vk_hash: pub Field,
) {
    // 1. Verify both wrapper_32 proofs.
    verify_honk_proof(w32_vk, w32_proof_a, w32_public_inputs_a, w32_vk_hash);
    verify_honk_proof(w32_vk, w32_proof_b, w32_public_inputs_b, w32_vk_hash);

    // 2. Re-fed arrays must match each half's committed hashes.
    assert(
        poseidon2_hash(nullifiers_a) == w32_public_inputs_a[2],
        "wrapper_64: nullifiers_a hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes_a) == w32_public_inputs_a[3],
        "wrapper_64: note_hashes_a hash mismatch",
    );
    assert(
        poseidon2_hash(deposits_a) == w32_public_inputs_a[4],
        "wrapper_64: deposits_a hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawals_a) == w32_public_inputs_a[5],
        "wrapper_64: withdrawals_a hash mismatch",
    );
    assert(
        poseidon2_hash(private_logs_a) == w32_public_inputs_a[6],
        "wrapper_64: private_logs_a hash mismatch",
    );

    assert(
        poseidon2_hash(nullifiers_b) == w32_public_inputs_b[2],
        "wrapper_64: nullifiers_b hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes_b) == w32_public_inputs_b[3],
        "wrapper_64: note_hashes_b hash mismatch",
    );
    assert(
        poseidon2_hash(deposits_b) == w32_public_inputs_b[4],
        "wrapper_64: deposits_b hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawals_b) == w32_public_inputs_b[5],
        "wrapper_64: withdrawals_b hash mismatch",
    );
    assert(
        poseidon2_hash(private_logs_b) == w32_public_inputs_b[6],
        "wrapper_64: private_logs_b hash mismatch",
    );

    // 3. State-root chain: B's old root == A's new root.
    assert(
        w32_public_inputs_a[1] == w32_public_inputs_b[0],
        "wrapper_64: state root chain broken",
    );

    // 4. Tree-index chain.
    let mut null_count_a: Field = 0;
    for i in 0..INNER_NULLIFIERS {
        if nullifiers_a[i] != 0 { null_count_a += 1; }
    }
    let mut nh_count_a: Field = 0;
    for i in 0..INNER_NOTE_HASHES {
        if note_hashes_a[i] != 0 { nh_count_a += 1; }
    }
    assert(
        w32_public_inputs_b[7] == w32_public_inputs_a[7] + null_count_a,
        "wrapper_64: nullifier tree index chain broken",
    );
    assert(
        w32_public_inputs_b[8] == w32_public_inputs_a[8] + nh_count_a,
        "wrapper_64: note hash tree index chain broken",
    );

    // 5. Build triply-merged arrays and compute combined hashes.
    let mut merged_nullifiers: [Field; BATCH_64_NULLIFIERS] = [0; BATCH_64_NULLIFIERS];
    let mut merged_note_hashes: [Field; BATCH_64_NOTE_HASHES] = [0; BATCH_64_NOTE_HASHES];
    let mut merged_deposits: [Field; BATCH_64_SIZE] = [0; BATCH_64_SIZE];
    let mut merged_withdrawals: [Field; BATCH_64_SIZE] = [0; BATCH_64_SIZE];
    let mut merged_private_logs: [Field; BATCH_64_LOGS_FLAT] = [0; BATCH_64_LOGS_FLAT];

    for i in 0..INNER_NULLIFIERS {
        merged_nullifiers[i] = nullifiers_a[i];
        merged_nullifiers[INNER_NULLIFIERS + i] = nullifiers_b[i];
    }
    for i in 0..INNER_NOTE_HASHES {
        merged_note_hashes[i] = note_hashes_a[i];
        merged_note_hashes[INNER_NOTE_HASHES + i] = note_hashes_b[i];
    }
    for i in 0..INNER_BATCH_SIZE {
        merged_deposits[i] = deposits_a[i];
        merged_deposits[INNER_BATCH_SIZE + i] = deposits_b[i];
        merged_withdrawals[i] = withdrawals_a[i];
        merged_withdrawals[INNER_BATCH_SIZE + i] = withdrawals_b[i];
    }
    for i in 0..INNER_LOGS_FLAT {
        merged_private_logs[i] = private_logs_a[i];
        merged_private_logs[INNER_LOGS_FLAT + i] = private_logs_b[i];
    }

    // 6. Expose merged public outputs.
    assert(old_state_root == w32_public_inputs_a[0], "wrapper_64: old state root mismatch");
    assert(new_state_root == w32_public_inputs_b[1], "wrapper_64: new state root mismatch");
    assert(
        merged_nullifiers_hash == poseidon2_hash(merged_nullifiers),
        "wrapper_64: merged nullifiers hash mismatch",
    );
    assert(
        merged_note_hashes_hash == poseidon2_hash(merged_note_hashes),
        "wrapper_64: merged note hashes hash mismatch",
    );
    assert(
        merged_deposit_nullifiers_hash == poseidon2_hash(merged_deposits),
        "wrapper_64: merged deposit nullifiers hash mismatch",
    );
    assert(
        merged_withdrawal_claims_hash == poseidon2_hash(merged_withdrawals),
        "wrapper_64: merged withdrawal claims hash mismatch",
    );
    assert(
        merged_private_logs_hash == poseidon2_hash(merged_private_logs),
        "wrapper_64: merged private logs hash mismatch",
    );
    assert(
        nullifier_tree_start_index == w32_public_inputs_a[7],
        "wrapper_64: nullifier tree start index mismatch",
    );
    assert(
        note_hash_tree_start_index == w32_public_inputs_a[8],
        "wrapper_64: note hash tree start index mismatch",
    );

    // 7. Full inner VK chain: both halves agreed on wrapper_vk_hash (PI[9])
    //    AND w16_vk_hash (PI[10]). Propagate those plus our own w32_vk_hash.
    assert(
        w32_public_inputs_a[9] == w32_public_inputs_b[9],
        "wrapper_64: inner wrapper_vk_hash mismatch between halves",
    );
    assert(
        w32_public_inputs_a[10] == w32_public_inputs_b[10],
        "wrapper_64: inner w16_vk_hash mismatch between halves",
    );
    assert(
        out_wrapper_vk_hash == w32_public_inputs_a[9],
        "wrapper_64: out wrapper vk hash mismatch",
    );
    assert(
        out_w16_vk_hash == w32_public_inputs_a[10],
        "wrapper_64: out w16 vk hash mismatch",
    );
    assert(
        out_w32_vk_hash == w32_vk_hash,
        "wrapper_64: out w32 vk hash mismatch",
    );
}
