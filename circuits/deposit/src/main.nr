use l3_types::{
    Note, MAX_NOTES_PER_TX, MAX_OUTPUTS_PER_TX, TX_LOG_PAYLOAD_LEN,
    hash_pubkey, poseidon2_hash,
};

// Deposit circuit: binds a pending L2 deposit (registered by the contract's
// deposit() function) to the L3 note it creates.
//
// Public inputs (6 fields, matching batch_app layout):
//   [deposit_hash, 0, l3_note_hash, 0, state_root, logs_commit]
//
// deposit_hash serves as the L3 nullifier for this slot (inserted into
// the L3 nullifier tree and checked against the pending deposits list).
fn main(
    // --- private inputs ---
    amount: Field,
    token_id: Field,
    l3_recipient_pubkey_x: Field,
    l3_recipient_pubkey_y: Field,
    salt: Field,
    private_logs: [Field; TX_LOG_PAYLOAD_LEN],
    // --- public inputs ---
    nullifiers: pub [Field; MAX_NOTES_PER_TX],
    note_hashes: pub [Field; MAX_OUTPUTS_PER_TX],
    state_root: pub Field, // unconstrained here; batch_app verifies it
    logs_commit: pub Field,
) {
    let _ = state_root;

    assert(poseidon2_hash(private_logs) == logs_commit, "logs commit mismatch");

    let recipient_pubkey_hash = hash_pubkey(l3_recipient_pubkey_x, l3_recipient_pubkey_y);

    // 1. deposit_hash matches what the L2 deposit() function registered.
    let deposit_hash = poseidon2_hash([recipient_pubkey_hash, amount, token_id, salt]);
    assert(deposit_hash == nullifiers[0], "deposit hash mismatch");

    // 2. Only one nullifier slot used.
    assert(nullifiers[1] == 0, "deposit uses one nullifier slot");

    // 3. L3 note correctly formed.
    let l3_note = Note {
        owner_pubkey_hash: recipient_pubkey_hash,
        amount,
        token_id,
        salt,
    };
    assert(l3_note.hash() == note_hashes[0], "l3 note hash mismatch");

    // 4. Only one output slot used.
    assert(note_hashes[1] == 0, "deposit produces one note");
}
