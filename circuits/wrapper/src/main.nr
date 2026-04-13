use l3_types::{ULTRA_HONK_VK_LENGTH, ULTRA_HONK_PROOF_LENGTH, BATCH_OUTPUT_FIELDS};
use bb_proof_verification::{verify_honk_proof, UltraHonkVerificationKey, UltraHonkZKProof};

fn main(
    // --- private inputs ---
    batch_app_vk: UltraHonkVerificationKey,
    batch_app_proof: UltraHonkZKProof,
    batch_app_public_inputs: [Field; BATCH_OUTPUT_FIELDS],
    batch_app_vk_hash: Field,
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
    // 1. Verify the batch_app UltraHonk proof.
    verify_honk_proof(
        batch_app_vk,
        batch_app_proof,
        batch_app_public_inputs,
        batch_app_vk_hash,
    );

    // 2. Assert public outputs match the batch_app public inputs.
    assert(batch_app_public_inputs[0] == old_state_root);
    assert(batch_app_public_inputs[1] == new_state_root);
    assert(batch_app_public_inputs[2] == nullifiers_batch_hash);
    assert(batch_app_public_inputs[3] == note_hashes_batch_hash);
    assert(batch_app_public_inputs[4] == deposit_nullifiers_hash);
    assert(batch_app_public_inputs[5] == withdrawal_claims_hash);
    assert(batch_app_public_inputs[6] == nullifier_tree_start_index);
    assert(batch_app_public_inputs[7] == note_hash_tree_start_index);
}
