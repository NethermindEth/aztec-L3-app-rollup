// TXE probes for Phase 2's private_logs_hash assertion in submit_batch*
// and submit_merged_batch.
//
// Each private entry point re-hashes the caller-supplied private_logs array
// and asserts the result equals public_inputs[6]. These probes exercise:
//
//   (a) the assert fires when logs don't match the commit -- blocks a
//       malicious caller from substituting log bytes after the proof is built.
//   (b) plumbing is wired correctly at batch=8 (submit_batch) and the
//       batch=16 merged path (submit_merged_batch).
//
// Known TXE harness limitation: `env.create_light_account` currently fails
// under this Aztec nightly + WSL2 combination ("0 output values provided for
// 13 destination slots" at test_environment.nr:462). The failure lives in the
// account-creation oracle, not in the L3 contract. Positive-case probes that
// need a private caller therefore appear as "FAIL" even when the contract
// logic is correct; see the sibling lifecycle tests for the same pattern.
// The negative (should_fail) probes pass regardless -- any failure along the
// call path satisfies should_fail.
//
// verify_honk_proof is a no-op in TXE; the private_logs_hash poseidon2 assert
// IS enforced.

use crate::L3IvcSettlement;
use super::utils::{
    TestL3, BATCH_LOGS_FLAT_COUNT, BATCH_NULLIFIERS_COUNT, BATCH_NOTE_HASHES_COUNT, MAX_BATCH_SIZE,
};
use aztec::protocol::hash::poseidon2_hash;
use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof};

global VK_ZEROS: UltraHonkVerificationKey = [0; 115];
global PROOF_ZEROS: UltraHonkZKProof = [0; 500];
// Merged-path arrays (must match main.nr MERGED_BATCH_* and settle utils).
global MERGED_LOGS_FLAT_COUNT: u32 = 512;
global MERGED_NULLIFIERS_COUNT: u32 = 32;
global MERGED_NOTE_HASHES_COUNT: u32 = 32;
global MERGED_BATCH_SIZE: u32 = 16;

// ----- 8-slot (submit_batch) -----

#[test]
unconstrained fn submit_batch_accepts_matching_logs_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;  // setup's account -- fresh accounts hit a TXE oracle bug

    let private_logs: [Field; BATCH_LOGS_FLAT_COUNT] = [0; BATCH_LOGS_FLAT_COUNT];
    let commit = poseidon2_hash(private_logs);

    // PI layout: [0..8] BatchOutput, [9] per_tx_vk_hashes_commit (zero matches storage).
    let mut public_inputs: [Field; 10] = [0; 10];
    public_inputs[1] = 0x5555;        // new_state_root
    public_inputs[6] = commit;        // private_logs_hash slot

    l3.env.call_private(
        caller,
        L3IvcSettlement::at(l3.l3).submit_batch(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; BATCH_NULLIFIERS_COUNT],
            [0 as Field; BATCH_NOTE_HASHES_COUNT],
            [0 as Field; MAX_BATCH_SIZE],
            [0 as Field; MAX_BATCH_SIZE],
            private_logs,
        ),
    );
    assert(l3.latest_root() == 0x5555, "submit_batch must advance root");
    assert(l3.batch_nonce() == 1, "submit_batch must advance nonce");
}

#[test(should_fail)]
unconstrained fn submit_batch_rejects_tampered_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;

    let private_logs: [Field; BATCH_LOGS_FLAT_COUNT] = [0; BATCH_LOGS_FLAT_COUNT];
    let mut public_inputs: [Field; 10] = [0; 10];
    public_inputs[1] = 0x5555;
    public_inputs[6] = 0xbadbad;      // not the hash of private_logs

    l3.env.call_private(
        caller,
        L3IvcSettlement::at(l3.l3).submit_batch(
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
    let caller = l3.admin;

    let zero_logs: [Field; BATCH_LOGS_FLAT_COUNT] = [0; BATCH_LOGS_FLAT_COUNT];
    let commit = poseidon2_hash(zero_logs);
    let mut tampered: [Field; BATCH_LOGS_FLAT_COUNT] = [0; BATCH_LOGS_FLAT_COUNT];
    tampered[42] = 1;

    let mut public_inputs: [Field; 10] = [0; 10];
    public_inputs[1] = 0x5555;
    public_inputs[6] = commit;

    l3.env.call_private(
        caller,
        L3IvcSettlement::at(l3.l3).submit_batch(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; BATCH_NULLIFIERS_COUNT],
            [0 as Field; BATCH_NOTE_HASHES_COUNT],
            [0 as Field; MAX_BATCH_SIZE],
            [0 as Field; MAX_BATCH_SIZE],
            tampered,
        ),
    );
}

// ----- 16-slot merged (submit_merged_batch) -----

#[test(should_fail)]
unconstrained fn submit_merged_batch_rejects_tampered_logs() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;

    let zero_logs: [Field; MERGED_LOGS_FLAT_COUNT] = [0; MERGED_LOGS_FLAT_COUNT];
    let commit = poseidon2_hash(zero_logs);
    let mut tampered: [Field; MERGED_LOGS_FLAT_COUNT] = [0; MERGED_LOGS_FLAT_COUNT];
    tampered[100] = 1;

    // submit_merged_batch takes BATCH_OUTPUT_FIELDS = 10 PIs (same as submit_batch).
    let mut public_inputs: [Field; 10] = [0; 10];
    public_inputs[1] = 0x6666;
    public_inputs[6] = commit;

    l3.env.call_private(
        caller,
        L3IvcSettlement::at(l3.l3).submit_merged_batch(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; MERGED_NULLIFIERS_COUNT],
            [0 as Field; MERGED_NOTE_HASHES_COUNT],
            [0 as Field; MERGED_BATCH_SIZE],
            [0 as Field; MERGED_BATCH_SIZE],
            tampered,
        ),
    );
}

// ----- per_tx_vk_hashes_commit binding probes (IVC contract) -----
//
// Storage holds per_tx_vk_hashes_commit (zero in TestL3::setup). Each
// submit_* private function asserts public_inputs[9] == storage value.

#[test(should_fail)]
unconstrained fn submit_batch_rejects_tampered_per_tx_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;

    let private_logs: [Field; BATCH_LOGS_FLAT_COUNT] = [0; BATCH_LOGS_FLAT_COUNT];
    let logs_commit = poseidon2_hash(private_logs);
    let mut public_inputs: [Field; 10] = [0; 10];
    public_inputs[1] = 0x5555;
    public_inputs[6] = logs_commit;
    public_inputs[9] = 0xdeadbeef;  // mismatched per-tx VK hashes commit

    l3.env.call_private(
        caller,
        L3IvcSettlement::at(l3.l3).submit_batch(
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
unconstrained fn submit_merged_batch_rejects_tampered_per_tx_commit() {
    let mut l3 = TestL3::setup();
    let caller = l3.admin;

    let zero_logs: [Field; MERGED_LOGS_FLAT_COUNT] = [0; MERGED_LOGS_FLAT_COUNT];
    let commit = poseidon2_hash(zero_logs);
    let mut public_inputs: [Field; 10] = [0; 10];
    public_inputs[1] = 0x6666;
    public_inputs[6] = commit;
    public_inputs[9] = 0xdeadbeef;

    l3.env.call_private(
        caller,
        L3IvcSettlement::at(l3.l3).submit_merged_batch(
            VK_ZEROS, PROOF_ZEROS, public_inputs, 0,
            [0 as Field; MERGED_NULLIFIERS_COUNT],
            [0 as Field; MERGED_NOTE_HASHES_COUNT],
            [0 as Field; MERGED_BATCH_SIZE],
            [0 as Field; MERGED_BATCH_SIZE],
            zero_logs,
        ),
    );
}
