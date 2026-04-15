// wrapper_32 -- recursive UltraHonk aggregator for 2 wrapper_16 proofs.
//
// Level 2 of the aggregation tree; intermediate only (no direct L2 submit
// target). Consumed by wrapper_64.
//
// Verifies two wrapper_16 proofs, re-feeds both halves' merged settle arrays
// for hash cross-check, chains state roots + tree indices, and exposes
// 32-slot doubly-merged BatchOutput plus the inner VK-hash chain.

use l3_types::poseidon2_hash;
use bb_proof_verification::{verify_honk_proof, UltraHonkVerificationKey, UltraHonkZKProof};

// Inner wrapper_16 sizes:
global INNER_BATCH_SIZE: u32 = 16;
global INNER_NULLIFIERS: u32 = 32;
global INNER_NOTE_HASHES: u32 = 32;

// Output (32-slot merged) array sizes:
global BATCH_32_SIZE: u32 = 32;
global BATCH_32_NULLIFIERS: u32 = 64;
global BATCH_32_NOTE_HASHES: u32 = 64;

// Inner wrapper_16 public-input layout (9 fields):
//   [0..7] BatchOutput
//   [8]    wrapper_vk_hash (inner VK binding from wrapper_16)
global INNER_PUB_COUNT: u32 = 9;

fn main(
    // --- private inputs ---
    // Shared wrapper_16 VK.
    w16_vk: UltraHonkVerificationKey,
    w16_vk_hash: Field,

    // Half A wrapper_16 proof + its public inputs.
    w16_proof_a: UltraHonkZKProof,
    w16_public_inputs_a: [Field; INNER_PUB_COUNT],

    // Half B wrapper_16 proof + its public inputs.
    w16_proof_b: UltraHonkZKProof,
    w16_public_inputs_b: [Field; INNER_PUB_COUNT],

    // Re-fed 16-slot-merged settle arrays from each half.
    nullifiers_a: [Field; INNER_NULLIFIERS],
    note_hashes_a: [Field; INNER_NOTE_HASHES],
    deposits_a: [Field; INNER_BATCH_SIZE],
    withdrawals_a: [Field; INNER_BATCH_SIZE],

    nullifiers_b: [Field; INNER_NULLIFIERS],
    note_hashes_b: [Field; INNER_NOTE_HASHES],
    deposits_b: [Field; INNER_BATCH_SIZE],
    withdrawals_b: [Field; INNER_BATCH_SIZE],

    // --- public outputs (32-slot doubly-merged + 2 VK-chain fields) ---
    old_state_root: pub Field,
    new_state_root: pub Field,
    merged_nullifiers_hash: pub Field,
    merged_note_hashes_hash: pub Field,
    merged_deposit_nullifiers_hash: pub Field,
    merged_withdrawal_claims_hash: pub Field,
    nullifier_tree_start_index: pub Field,
    note_hash_tree_start_index: pub Field,
    out_wrapper_vk_hash: pub Field,  // wrapper VK hash propagated from inner
    out_w16_vk_hash: pub Field,      // wrapper_16 VK hash this proof aggregated over
) {
    // 1. Verify both wrapper_16 proofs.
    verify_honk_proof(w16_vk, w16_proof_a, w16_public_inputs_a, w16_vk_hash);
    verify_honk_proof(w16_vk, w16_proof_b, w16_public_inputs_b, w16_vk_hash);

    // 2. Re-fed arrays must match each half's committed hashes.
    assert(
        poseidon2_hash(nullifiers_a) == w16_public_inputs_a[2],
        "wrapper_32: nullifiers_a hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes_a) == w16_public_inputs_a[3],
        "wrapper_32: note_hashes_a hash mismatch",
    );
    assert(
        poseidon2_hash(deposits_a) == w16_public_inputs_a[4],
        "wrapper_32: deposits_a hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawals_a) == w16_public_inputs_a[5],
        "wrapper_32: withdrawals_a hash mismatch",
    );

    assert(
        poseidon2_hash(nullifiers_b) == w16_public_inputs_b[2],
        "wrapper_32: nullifiers_b hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes_b) == w16_public_inputs_b[3],
        "wrapper_32: note_hashes_b hash mismatch",
    );
    assert(
        poseidon2_hash(deposits_b) == w16_public_inputs_b[4],
        "wrapper_32: deposits_b hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawals_b) == w16_public_inputs_b[5],
        "wrapper_32: withdrawals_b hash mismatch",
    );

    // 3. State-root chain: B's old root == A's new root.
    assert(
        w16_public_inputs_a[1] == w16_public_inputs_b[0],
        "wrapper_32: state root chain broken",
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
        w16_public_inputs_b[6] == w16_public_inputs_a[6] + null_count_a,
        "wrapper_32: nullifier tree index chain broken",
    );
    assert(
        w16_public_inputs_b[7] == w16_public_inputs_a[7] + nh_count_a,
        "wrapper_32: note hash tree index chain broken",
    );

    // 5. Build doubly-merged arrays and compute combined hashes.
    let mut merged_nullifiers: [Field; BATCH_32_NULLIFIERS] = [0; BATCH_32_NULLIFIERS];
    let mut merged_note_hashes: [Field; BATCH_32_NOTE_HASHES] = [0; BATCH_32_NOTE_HASHES];
    let mut merged_deposits: [Field; BATCH_32_SIZE] = [0; BATCH_32_SIZE];
    let mut merged_withdrawals: [Field; BATCH_32_SIZE] = [0; BATCH_32_SIZE];

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

    // 6. Expose merged public outputs.
    assert(old_state_root == w16_public_inputs_a[0], "wrapper_32: old state root mismatch");
    assert(new_state_root == w16_public_inputs_b[1], "wrapper_32: new state root mismatch");
    assert(
        merged_nullifiers_hash == poseidon2_hash(merged_nullifiers),
        "wrapper_32: merged nullifiers hash mismatch",
    );
    assert(
        merged_note_hashes_hash == poseidon2_hash(merged_note_hashes),
        "wrapper_32: merged note hashes hash mismatch",
    );
    assert(
        merged_deposit_nullifiers_hash == poseidon2_hash(merged_deposits),
        "wrapper_32: merged deposit nullifiers hash mismatch",
    );
    assert(
        merged_withdrawal_claims_hash == poseidon2_hash(merged_withdrawals),
        "wrapper_32: merged withdrawal claims hash mismatch",
    );
    assert(
        nullifier_tree_start_index == w16_public_inputs_a[6],
        "wrapper_32: nullifier tree start index mismatch",
    );
    assert(
        note_hash_tree_start_index == w16_public_inputs_a[7],
        "wrapper_32: note hash tree start index mismatch",
    );

    // 7. Inner VK chain: both halves agreed on wrapper_vk_hash (PI[8]).
    //    Propagate it plus our own w16_vk_hash so wrapper_64 / contract
    //    can bind both levels.
    assert(
        w16_public_inputs_a[8] == w16_public_inputs_b[8],
        "wrapper_32: inner wrapper_vk_hash mismatch between halves",
    );
    assert(
        out_wrapper_vk_hash == w16_public_inputs_a[8],
        "wrapper_32: out wrapper vk hash mismatch",
    );
    assert(
        out_w16_vk_hash == w16_vk_hash,
        "wrapper_32: out w16 vk hash mismatch",
    );
}
