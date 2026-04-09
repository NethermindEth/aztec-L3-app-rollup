use l3_types::{MAX_NOTES_PER_TX, MAX_OUTPUTS_PER_TX};

// Padding circuit: fills unused batch slots with a trivially-provable circuit.
// All public inputs must be zero. The batch_app verifies this proof with the
// padding VK and skips insertion for zero-valued slots.
fn main(
    nullifiers: pub [Field; MAX_NOTES_PER_TX],
    note_hashes: pub [Field; MAX_OUTPUTS_PER_TX],
    state_root: pub Field,
) {
    for i in 0..MAX_NOTES_PER_TX {
        assert(nullifiers[i] == 0);
    }
    for i in 0..MAX_OUTPUTS_PER_TX {
        assert(note_hashes[i] == 0);
    }
    assert(state_root == 0);
}
