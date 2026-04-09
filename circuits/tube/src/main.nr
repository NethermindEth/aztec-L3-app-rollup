use l3_types::{MEGA_VK_LENGTH, CHONK_PROOF_LENGTH, BATCH_OUTPUT_FIELDS, PROOF_TYPE_CHONK};

fn main(
    // --- private inputs ---
    verification_key: [Field; MEGA_VK_LENGTH],
    proof: [Field; CHONK_PROOF_LENGTH],
    chonk_public_inputs: [Field; BATCH_OUTPUT_FIELDS],
    key_hash: Field,
    // --- public inputs ---
    old_state_root: pub Field,
    new_state_root: pub Field,
    nullifiers_batch_hash: pub Field,
    note_hashes_batch_hash: pub Field,
    deposit_nullifiers_hash: pub Field,
    withdrawal_claims_hash: pub Field,
    nullifier_tree_start_index: pub Field,
    note_hash_tree_start_index: pub Field,
) {
    // 1. Verify the Chonk proof from the IVC hiding kernel.
    std::verify_proof_with_type(
        verification_key,
        proof,
        chonk_public_inputs,
        key_hash,
        PROOF_TYPE_CHONK,
    );

    // 2. Assert public outputs match the Chonk public inputs.
    assert(chonk_public_inputs[0] == old_state_root);
    assert(chonk_public_inputs[1] == new_state_root);
    assert(chonk_public_inputs[2] == nullifiers_batch_hash);
    assert(chonk_public_inputs[3] == note_hashes_batch_hash);
    assert(chonk_public_inputs[4] == deposit_nullifiers_hash);
    assert(chonk_public_inputs[5] == withdrawal_claims_hash);
    assert(chonk_public_inputs[6] == nullifier_tree_start_index);
    assert(chonk_public_inputs[7] == note_hash_tree_start_index);
}
