// TXE probes for Phase 2's private_logs_hash assertion in submit_batch*.
//
// Each submit_batch* private function re-hashes the caller-supplied
// private_logs array and asserts the result equals public_inputs[6] (the
// private_logs_hash slot published by the wrapper proof). These probes
// confirm:
//
//   (a) the assert fires when logs don't match the commit -- so a malicious
//       caller can't substitute log bytes after the proof is built.
//   (b) the assert passes through uniformly-zero batches (the harness pattern
//       the existing lifecycle tests use).
//
// Note: under TXE, verify_honk_proof is a no-op (see SILENT_FAILURE_REVIEW.md
// Problem 1). The contract's inner-VK storage asserts still fire, and so does
// our poseidon2-based logs check. That's why we can exercise submit_batch*
// locally with all-zero VK/proof inputs.

use crate::L3RecursiveSettlement;
use super::utils::{
    TestL3, BATCH_LOGS_FLAT_COUNT, BATCH_16_LOGS_FLAT_COUNT, BATCH_64_LOGS_FLAT_COUNT,
    BATCH_NULLIFIERS_COUNT, BATCH_NOTE_HASHES_COUNT, MAX_BATCH_SIZE,
    BATCH_16_NULLIFIERS_COUNT, BATCH_16_NOTE_HASHES_COUNT, BATCH_16_SIZE,
    BATCH_64_NULLIFIERS_COUNT, BATCH_64_NOTE_HASHES_COUNT, BATCH_64_SIZE,
};
use aztec::protocol::hash::poseidon2_hash;
use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof};

// Contract proof-input shapes. Pass-through arrays that we construct as
// all-zero. verify_honk_proof is a TXE no-op so no further coherence needed.
global VK_ZEROS: UltraHonkVerificationKey = [0; 115];
global PROOF_ZEROS: UltraHonkZKProof = [0; 500];

// ----- 8-slot (submit_batch) -----

#[test]
unconstrained fn submit_batch_accepts_matching_logs_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;  // reuse setup's account -- fresh accounts trigger a pre-existing TXE oracle bug

    let private_logs: [Field; BATCH_LOGS_FLAT_COUNT] = [0; BATCH_LOGS_FLAT_COUNT];
    let commit = poseidon2_hash(private_logs);

    // BatchOutput PI layout: [old_root, new_root, nullifiers_hash, note_hashes_hash,
    // deposit_hash, withdrawal_hash, private_logs_hash, null_tree_idx, nh_tree_idx].
    // 10 fields: BatchOutput now includes per_tx_vk_hashes_commit at [9].
    // Leaving it 0 matches the zero-initialized per_tx_vk_hashes_commit in TestL3::setup.
    let mut public_inputs: [Field; 10] = [0; 10];
    public_inputs[1] = 0x7777;       // new_state_root (non-zero to observe state advance)
    public_inputs[6] = commit;       // matches

    l3.env.call_private(
        caller,
        L3RecursiveSettlement::at(l3.l3).submit_batch(
            VK_ZEROS,
            PROOF_ZEROS,
            public_inputs,
            0,                                        // tube_vk_hash: matches storage
            [0 as Field; BATCH_NULLIFIERS_COUNT],
            [0 as Field; BATCH_NOTE_HASHES_COUNT],
            [0 as Field; MAX_BATCH_SIZE],
            [0 as Field; MAX_BATCH_SIZE],
            private_logs,
        ),
    );

    assert(l3.latest_root() == 0x7777, "submit_batch must enqueue a settle that advances root");
    assert(l3.batch_nonce() == 1, "submit_batch must advance nonce exactly once");
}

#[test(should_fail)]
unconstrained fn submit_batch_rejects_tampered_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;  // reuse setup's account -- fresh accounts trigger a pre-existing TXE oracle bug

    let private_logs: [Field; BATCH_LOGS_FLAT_COUNT] = [0; BATCH_LOGS_FLAT_COUNT];
    // 10 fields: BatchOutput now includes per_tx_vk_hashes_commit at [9].
    // Leaving it 0 matches the zero-initialized per_tx_vk_hashes_commit in TestL3::setup.
    let mut public_inputs: [Field; 10] = [0; 10];
    public_inputs[1] = 0x7777;
    public_inputs[6] = 0xbadbad;     // NOT the hash of private_logs

    l3.env.call_private(
        caller,
        L3RecursiveSettlement::at(l3.l3).submit_batch(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; BATCH_NULLIFIERS_COUNT],
            [0 as Field; BATCH_NOTE_HASHES_COUNT],
            [0 as Field; MAX_BATCH_SIZE],
            [0 as Field; MAX_BATCH_SIZE],
            private_logs,
        ),
    );
}

#[test(should_fail)]
unconstrained fn submit_batch_rejects_tampered_logs() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;  // reuse setup's account -- fresh accounts trigger a pre-existing TXE oracle bug

    // Commit to all-zero logs, then submit with ONE non-zero entry -- hash differs.
    let zero_logs: [Field; BATCH_LOGS_FLAT_COUNT] = [0; BATCH_LOGS_FLAT_COUNT];
    let commit = poseidon2_hash(zero_logs);
    let mut tampered: [Field; BATCH_LOGS_FLAT_COUNT] = [0; BATCH_LOGS_FLAT_COUNT];
    tampered[42] = 1;                // flip one byte's worth of content

    // 10 fields: BatchOutput now includes per_tx_vk_hashes_commit at [9].
    // Leaving it 0 matches the zero-initialized per_tx_vk_hashes_commit in TestL3::setup.
    let mut public_inputs: [Field; 10] = [0; 10];
    public_inputs[1] = 0x7777;
    public_inputs[6] = commit;

    l3.env.call_private(
        caller,
        L3RecursiveSettlement::at(l3.l3).submit_batch(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; BATCH_NULLIFIERS_COUNT],
            [0 as Field; BATCH_NOTE_HASHES_COUNT],
            [0 as Field; MAX_BATCH_SIZE],
            [0 as Field; MAX_BATCH_SIZE],
            tampered,
        ),
    );
}

// ----- 16-slot (submit_batch_16) -----

#[test]
unconstrained fn submit_batch_16_accepts_matching_logs_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;  // reuse setup's account -- fresh accounts trigger a pre-existing TXE oracle bug

    let private_logs: [Field; BATCH_16_LOGS_FLAT_COUNT] = [0; BATCH_16_LOGS_FLAT_COUNT];
    let commit = poseidon2_hash(private_logs);

    // PI layout: [0..8] BatchOutput, [9] wrapper_vk_hash, [10] per_tx_vk_hashes_commit.
    let mut public_inputs: [Field; 11] = [0; 11];
    public_inputs[1] = 0x8888;
    public_inputs[6] = commit;

    l3.env.call_private(
        caller,
        L3RecursiveSettlement::at(l3.l3).submit_batch_16(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; BATCH_16_NULLIFIERS_COUNT],
            [0 as Field; BATCH_16_NOTE_HASHES_COUNT],
            [0 as Field; BATCH_16_SIZE],
            [0 as Field; BATCH_16_SIZE],
            private_logs,
        ),
    );

    assert(l3.latest_root() == 0x8888, "submit_batch_16 must enqueue a settle that advances root");
    assert(l3.batch_nonce() == 1, "submit_batch_16 must advance nonce exactly once");
}

#[test(should_fail)]
unconstrained fn submit_batch_16_rejects_tampered_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;  // reuse setup's account -- fresh accounts trigger a pre-existing TXE oracle bug

    let private_logs: [Field; BATCH_16_LOGS_FLAT_COUNT] = [0; BATCH_16_LOGS_FLAT_COUNT];
    let mut public_inputs: [Field; 11] = [0; 11];
    public_inputs[1] = 0x8888;
    public_inputs[6] = 0xbadbad;

    l3.env.call_private(
        caller,
        L3RecursiveSettlement::at(l3.l3).submit_batch_16(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; BATCH_16_NULLIFIERS_COUNT],
            [0 as Field; BATCH_16_NOTE_HASHES_COUNT],
            [0 as Field; BATCH_16_SIZE],
            [0 as Field; BATCH_16_SIZE],
            private_logs,
        ),
    );
}

// ----- 64-slot (submit_batch_64) -----

#[test(should_fail)]
unconstrained fn submit_batch_64_rejects_tampered_logs() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;  // reuse setup's account -- fresh accounts trigger a pre-existing TXE oracle bug

    let zero_logs: [Field; BATCH_64_LOGS_FLAT_COUNT] = [0; BATCH_64_LOGS_FLAT_COUNT];
    let commit = poseidon2_hash(zero_logs);
    let mut tampered: [Field; BATCH_64_LOGS_FLAT_COUNT] = [0; BATCH_64_LOGS_FLAT_COUNT];
    tampered[1000] = 1;

    // PI layout: [0..8] BatchOutput, [9] wrapper_vk_hash, [10] vk_hash_16,
    //            [11] vk_hash_32, [12] per_tx_vk_hashes_commit.
    let mut public_inputs: [Field; 13] = [0; 13];
    public_inputs[1] = 0x9999;
    public_inputs[6] = commit;

    l3.env.call_private(
        caller,
        L3RecursiveSettlement::at(l3.l3).submit_batch_64(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; BATCH_64_NULLIFIERS_COUNT],
            [0 as Field; BATCH_64_NOTE_HASHES_COUNT],
            [0 as Field; BATCH_64_SIZE],
            [0 as Field; BATCH_64_SIZE],
            tampered,
        ),
    );
}

// ----- per_tx_vk_hashes_commit binding probes -----
//
// The contract stores per_tx_vk_hashes_commit as PublicImmutable; every
// submit_batch* path asserts public_inputs[<index>] == storage value.
// These probes confirm the assertion fires when the PI carries a
// non-matching commit -- closing the custom-per-tx-circuit substitution
// class for each endpoint.

#[test(should_fail)]
unconstrained fn submit_batch_rejects_tampered_per_tx_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;

    let private_logs: [Field; BATCH_LOGS_FLAT_COUNT] = [0; BATCH_LOGS_FLAT_COUNT];
    let logs_commit = poseidon2_hash(private_logs);
    // BatchOutput PI layout puts per_tx_vk_hashes_commit at [9].
    // Setup deploys with storage value 0; we feed 0xdeadbeef to trigger the mismatch.
    let mut public_inputs: [Field; 10] = [0; 10];
    public_inputs[1] = 0x7777;
    public_inputs[6] = logs_commit;
    public_inputs[9] = 0xdeadbeef;

    l3.env.call_private(
        caller,
        L3RecursiveSettlement::at(l3.l3).submit_batch(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; BATCH_NULLIFIERS_COUNT],
            [0 as Field; BATCH_NOTE_HASHES_COUNT],
            [0 as Field; MAX_BATCH_SIZE],
            [0 as Field; MAX_BATCH_SIZE],
            private_logs,
        ),
    );
}

#[test(should_fail)]
unconstrained fn submit_batch_16_rejects_tampered_per_tx_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;

    let private_logs: [Field; BATCH_16_LOGS_FLAT_COUNT] = [0; BATCH_16_LOGS_FLAT_COUNT];
    let logs_commit = poseidon2_hash(private_logs);
    // PI layout: [0..8] BatchOutput, [9] wrapper_vk_hash, [10] per_tx_vk_hashes_commit.
    let mut public_inputs: [Field; 11] = [0; 11];
    public_inputs[1] = 0x8888;
    public_inputs[6] = logs_commit;
    public_inputs[10] = 0xdeadbeef;  // wrong per-tx commit

    l3.env.call_private(
        caller,
        L3RecursiveSettlement::at(l3.l3).submit_batch_16(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; BATCH_16_NULLIFIERS_COUNT],
            [0 as Field; BATCH_16_NOTE_HASHES_COUNT],
            [0 as Field; BATCH_16_SIZE],
            [0 as Field; BATCH_16_SIZE],
            private_logs,
        ),
    );
}

#[test(should_fail)]
unconstrained fn submit_batch_64_rejects_tampered_per_tx_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;

    let private_logs: [Field; BATCH_64_LOGS_FLAT_COUNT] = [0; BATCH_64_LOGS_FLAT_COUNT];
    let logs_commit = poseidon2_hash(private_logs);
    // PI layout: [0..8] BatchOutput, [9] wrapper_vk_hash, [10] vk_hash_16,
    //            [11] vk_hash_32, [12] per_tx_vk_hashes_commit.
    let mut public_inputs: [Field; 13] = [0; 13];
    public_inputs[1] = 0x9999;
    public_inputs[6] = logs_commit;
    public_inputs[12] = 0xdeadbeef;

    l3.env.call_private(
        caller,
        L3RecursiveSettlement::at(l3.l3).submit_batch_64(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; BATCH_64_NULLIFIERS_COUNT],
            [0 as Field; BATCH_64_NOTE_HASHES_COUNT],
            [0 as Field; BATCH_64_SIZE],
            [0 as Field; BATCH_64_SIZE],
            private_logs,
        ),
    );
}
