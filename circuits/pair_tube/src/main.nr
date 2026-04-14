// pair_tube -- recursive RollupHonk aggregator for 2 IVC tube proofs.
//
// Structurally identical to pair_wrapper, but uses verify_rolluphonk_proof
// with RollupHonkProof (519 fields) instead of verify_honk_proof with
// UltraHonkZKProof (500 fields). This allows verifying tube proofs generated
// at noir-rollup target, which carry IPA accumulation material from the
// Chonk compression step.
//
// Verifies two tube proofs, re-feeds both batches' settle-data arrays so
// that their poseidon2 hashes can be cross-checked, chains the state roots and
// tree indices, and exposes merged batch=16-equivalent public inputs.

use l3_types::poseidon2_hash;
use bb_proof_verification::{verify_rolluphonk_proof, RollupHonkVerificationKey, RollupHonkProof};

// These MUST match circuits/batch_app globals (batch=8):
global SUB_BATCH_SIZE: u32 = 8;
global SUB_BATCH_NULLIFIERS: u32 = 16;  // SUB_BATCH_SIZE * 2
global SUB_BATCH_NOTE_HASHES: u32 = 16; // SUB_BATCH_SIZE * 2

// Merged-batch array sizes (doubled):
global MERGED_BATCH_SIZE: u32 = 16;
global MERGED_BATCH_NULLIFIERS: u32 = 32;
global MERGED_BATCH_NOTE_HASHES: u32 = 32;

// Tube BatchOutput layout (shared between A and B tube proofs):
//   [0] old_state_root
//   [1] new_state_root
//   [2] nullifiers_batch_hash
//   [3] note_hashes_batch_hash
//   [4] deposit_nullifiers_hash
//   [5] withdrawal_claims_hash
//   [6] nullifier_tree_start_index
//   [7] note_hash_tree_start_index
global TUBE_PUB_COUNT: u32 = 8;

fn main(
    // --- private inputs ---
    // Shared tube VK (both sub-batches use the same tube circuit).
    tube_vk: RollupHonkVerificationKey,
    tube_vk_hash: Field,

    // Batch A tube proof + its public inputs.
    tube_proof_a: RollupHonkProof,
    tube_public_inputs_a: [Field; TUBE_PUB_COUNT],

    // Batch B tube proof + its public inputs.
    tube_proof_b: RollupHonkProof,
    tube_public_inputs_b: [Field; TUBE_PUB_COUNT],

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
    // 1. Verify both tube proofs against the shared VK.
    verify_rolluphonk_proof(tube_vk, tube_proof_a, tube_public_inputs_a, tube_vk_hash);
    verify_rolluphonk_proof(tube_vk, tube_proof_b, tube_public_inputs_b, tube_vk_hash);

    // 2. Re-fed arrays must match each tube's committed hashes.
    assert(
        poseidon2_hash(nullifiers_a) == tube_public_inputs_a[2],
        "pair_tube: nullifiers_a hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes_a) == tube_public_inputs_a[3],
        "pair_tube: note_hashes_a hash mismatch",
    );
    assert(
        poseidon2_hash(deposits_a) == tube_public_inputs_a[4],
        "pair_tube: deposits_a hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawals_a) == tube_public_inputs_a[5],
        "pair_tube: withdrawals_a hash mismatch",
    );

    assert(
        poseidon2_hash(nullifiers_b) == tube_public_inputs_b[2],
        "pair_tube: nullifiers_b hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes_b) == tube_public_inputs_b[3],
        "pair_tube: note_hashes_b hash mismatch",
    );
    assert(
        poseidon2_hash(deposits_b) == tube_public_inputs_b[4],
        "pair_tube: deposits_b hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawals_b) == tube_public_inputs_b[5],
        "pair_tube: withdrawals_b hash mismatch",
    );

    // 3. State-root chain: B's old root == A's new root.
    assert(
        tube_public_inputs_a[1] == tube_public_inputs_b[0],
        "pair_tube: state root chain broken",
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
        tube_public_inputs_b[6] == tube_public_inputs_a[6] + null_count_a,
        "pair_tube: nullifier tree index chain broken",
    );
    assert(
        tube_public_inputs_b[7] == tube_public_inputs_a[7] + nh_count_a,
        "pair_tube: note hash tree index chain broken",
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
    assert(old_state_root == tube_public_inputs_a[0], "pair_tube: old state root mismatch");
    assert(new_state_root == tube_public_inputs_b[1], "pair_tube: new state root mismatch");
    assert(
        merged_nullifiers_hash == poseidon2_hash(merged_nullifiers),
        "pair_tube: merged nullifiers hash mismatch",
    );
    assert(
        merged_note_hashes_hash == poseidon2_hash(merged_note_hashes),
        "pair_tube: merged note hashes hash mismatch",
    );
    assert(
        merged_deposit_nullifiers_hash == poseidon2_hash(merged_deposits),
        "pair_tube: merged deposit nullifiers hash mismatch",
    );
    assert(
        merged_withdrawal_claims_hash == poseidon2_hash(merged_withdrawals),
        "pair_tube: merged withdrawal claims hash mismatch",
    );
    assert(
        nullifier_tree_start_index == tube_public_inputs_a[6],
        "pair_tube: nullifier tree start index mismatch",
    );
    assert(
        note_hash_tree_start_index == tube_public_inputs_a[7],
        "pair_tube: note hash tree start index mismatch",
    );
}
