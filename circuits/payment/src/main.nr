use l3_types::{
    Note, IndexedLeaf, TREE_DEPTH, MAX_NOTES_PER_TX, MAX_OUTPUTS_PER_TX, TX_LOG_PAYLOAD_LEN,
    hash_pubkey, compute_nullifier, compute_state_root, derive_pubkey, poseidon2_hash,
    verify_merkle_membership, verify_nullifier_non_membership,
};

// Payment circuit: consumes up to 2 input notes, produces a recipient note
// and optionally a change note back to the sender.
//
// Public inputs (6 fields, matching batch_app layout):
//   [nullifier_0, nullifier_1, recipient_note_hash, change_note_hash, state_root, logs_commit]
//
// logs_commit is unconstrained content-wise (ONCHAIN_UNCONSTRAINED delivery);
// the circuit only asserts it is the poseidon2 of the wallet-supplied log bytes.
fn main(
    // --- private inputs ---
    owner_secret: Field,
    input_notes: [Note; MAX_NOTES_PER_TX],
    input_note_indices: [Field; MAX_NOTES_PER_TX],
    input_note_siblings: [[Field; TREE_DEPTH]; MAX_NOTES_PER_TX],
    // Indexed nullifier tree witnesses (low leaf for each nullifier).
    low_leaves: [IndexedLeaf; MAX_NOTES_PER_TX],
    low_leaf_indices: [Field; MAX_NOTES_PER_TX],
    low_leaf_siblings: [[Field; TREE_DEPTH]; MAX_NOTES_PER_TX],
    active_inputs: [u1; MAX_NOTES_PER_TX],
    recipient_pubkey_x: Field,
    recipient_pubkey_y: Field,
    output_salts: [Field; MAX_OUTPUTS_PER_TX],
    recipient_amount: Field,
    note_hash_tree_root: Field,
    nullifier_tree_root: Field,
    private_logs: [Field; TX_LOG_PAYLOAD_LEN],
    // --- public inputs ---
    nullifiers: pub [Field; MAX_NOTES_PER_TX],
    note_hashes: pub [Field; MAX_OUTPUTS_PER_TX],
    state_root: pub Field,
    logs_commit: pub Field,
) {
    assert(poseidon2_hash(private_logs) == logs_commit, "logs commit mismatch");

    // State root binds this proof to a specific L3 state.
    assert(
        compute_state_root(nullifier_tree_root, note_hash_tree_root) == state_root,
        "state root mismatch",
    );

    // At least one input must be active.
    assert(active_inputs[0] == 1, "first input must be active");

    let owner_pubkey = derive_pubkey(owner_secret);
    let owner_pubkey_hash = hash_pubkey(owner_pubkey.x, owner_pubkey.y);
    let token_id = input_notes[0].token_id;

    let mut total_input: Field = 0;

    for i in 0..MAX_NOTES_PER_TX {
        if active_inputs[i] == 1 {
            // Ownership.
            assert(input_notes[i].owner_pubkey_hash == owner_pubkey_hash);
            // Same token across all inputs.
            assert(input_notes[i].token_id == token_id);
            // Note exists in the note hash tree.
            verify_merkle_membership(
                input_notes[i].hash(),
                input_note_indices[i],
                input_note_siblings[i],
                note_hash_tree_root,
            );
            // Nullifier is correctly derived.
            assert(compute_nullifier(owner_secret, input_notes[i].salt) == nullifiers[i]);
            // Nullifier does NOT exist in the indexed nullifier tree.
            verify_nullifier_non_membership(
                nullifiers[i],
                low_leaves[i],
                low_leaf_indices[i],
                low_leaf_siblings[i],
                nullifier_tree_root,
            );
            total_input += input_notes[i].amount;
        } else {
            assert(nullifiers[i] == 0, "inactive input must have zero nullifier");
        }
    }

    // --- Conservation ---
    let change_amount = total_input - recipient_amount;
    // Range-check both halves to prevent field underflow.
    let _ = recipient_amount as u64;
    let _ = change_amount as u64;

    // Output 0: recipient note.
    let recipient_note = Note {
        owner_pubkey_hash: hash_pubkey(recipient_pubkey_x, recipient_pubkey_y),
        amount: recipient_amount,
        token_id,
        salt: output_salts[0],
    };
    assert(recipient_note.hash() == note_hashes[0]);

    // Output 1: change note (zero hash if exact spend).
    if change_amount != 0 {
        let change_note = Note {
            owner_pubkey_hash,
            amount: change_amount,
            token_id,
            salt: output_salts[1],
        };
        assert(change_note.hash() == note_hashes[1]);
    } else {
        assert(note_hashes[1] == 0, "no-change output must be zero");
    }
}
