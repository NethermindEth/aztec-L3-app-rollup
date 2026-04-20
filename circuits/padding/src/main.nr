use l3_types::{MAX_NOTES_PER_TX, MAX_OUTPUTS_PER_TX, TX_LOG_PAYLOAD_LEN, poseidon2_hash};

// Padding circuit: fills unused batch slots with a trivially-provable circuit.
// State-side public inputs must be zero; the log payload is free so that
// padding slots can carry random privacy-preserving logs (matching Aztec's
// uniform-size log privacy model). batch_app aggregates padding logs_commit
// into the batch private_logs_hash like any other slot.
fn main(
    private_logs: [Field; TX_LOG_PAYLOAD_LEN],
    nullifiers: pub [Field; MAX_NOTES_PER_TX],
    note_hashes: pub [Field; MAX_OUTPUTS_PER_TX],
    state_root: pub Field,
    logs_commit: pub Field,
) {
    for i in 0..MAX_NOTES_PER_TX {
        assert(nullifiers[i] == 0);
    }
    for i in 0..MAX_OUTPUTS_PER_TX {
        assert(note_hashes[i] == 0);
    }
    assert(state_root == 0);
    assert(poseidon2_hash(private_logs) == logs_commit, "logs commit mismatch");
}
