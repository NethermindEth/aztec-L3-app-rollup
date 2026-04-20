use l3_types::{
    TREE_DEPTH, MAX_NOTES_PER_TX, MAX_OUTPUTS_PER_TX, TX_PUBLIC_INPUT_COUNT,
    TX_LOG_PAYLOAD_LEN, TX_LOGS_COMMIT_INDEX,
    BatchOutput, IndexedLeaf, poseidon2_hash,
    compute_per_tx_vk_hashes_commit,
    compute_state_root, compute_merkle_root,
};
use bb_proof_verification::{verify_honk_proof, UltraHonkVerificationKey, UltraHonkZKProof};

// IVC pipeline batch sizes. Bounded by the Chonk ECCVM circuit limit of 32768 rows;
// batch=8 is experimental -- verify Chonk prove doesn't overflow ECCVM at this size.
global MAX_BATCH_SIZE: u32 = 8;
global BATCH_NULLIFIERS_COUNT: u32 = 16; // MAX_BATCH_SIZE * MAX_NOTES_PER_TX
global BATCH_NOTE_HASHES_COUNT: u32 = 16; // MAX_BATCH_SIZE * MAX_OUTPUTS_PER_TX
global BATCH_LOGS_FLAT_LEN: u32 = 256;    // MAX_BATCH_SIZE * TX_LOG_PAYLOAD_LEN = 8 * 32

fn main(
    // --- private inputs ---

    // Section VKs -- one per tx type.
    deposit_vk: UltraHonkVerificationKey,
    deposit_vk_hash: Field,
    payment_vk: UltraHonkVerificationKey,
    payment_vk_hash: Field,
    withdraw_vk: UltraHonkVerificationKey,
    withdraw_vk_hash: Field,
    padding_vk: UltraHonkVerificationKey,
    padding_vk_hash: Field,

    // Section boundary counts.
    // Batch layout: [deposits | payments | withdrawals | padding]
    deposit_count: u32,
    payment_count: u32,
    withdraw_count: u32,

    // Per-slot proof data.
    tx_proofs: [UltraHonkZKProof; MAX_BATCH_SIZE],
    tx_public_inputs: [[Field; TX_PUBLIC_INPUT_COUNT]; MAX_BATCH_SIZE],

    // Tree state.
    old_nullifier_tree_root: Field,
    old_note_hash_tree_root: Field,
    new_nullifier_tree_root: Field,
    new_note_hash_tree_root: Field,

    // -- Indexed nullifier tree insertion witnesses --
    // For each nullifier slot: the low leaf (predecessor in sorted order),
    // its Merkle siblings, and the Merkle siblings for the new leaf position.
    nullifier_low_leaves: [IndexedLeaf; BATCH_NULLIFIERS_COUNT],
    nullifier_low_leaf_indices: [Field; BATCH_NULLIFIERS_COUNT],
    nullifier_low_leaf_siblings: [[Field; TREE_DEPTH]; BATCH_NULLIFIERS_COUNT],
    nullifier_new_leaf_siblings: [[Field; TREE_DEPTH]; BATCH_NULLIFIERS_COUNT],

    // -- Append-only note hash tree insertion witnesses --
    note_hash_insertion_siblings: [[Field; TREE_DEPTH]; BATCH_NOTE_HASHES_COUNT],

    // -- Per-tx encrypted log payloads (witness) --
    // Shape: [MAX_BATCH_SIZE tx slots][MAX_OUTPUTS_PER_TX * PRIVATE_LOG_SIZE_IN_FIELDS = 32].
    // The per-tx circuit has already asserted poseidon2_hash(private_logs[i]) equals
    // its logs_commit public input; batch_app just re-checks + aggregates.
    private_logs: [[Field; TX_LOG_PAYLOAD_LEN]; MAX_BATCH_SIZE],

    // These 10 fields flow to the next kernel via return_data BatchOutput.
    // They are NOT declared pub because in the IVC context, pub inputs inflate
    // the VK's num_public_inputs beyond the IVC IO size, breaking accumulation.
    // The values are still constrained by asserts in the circuit body.
    old_state_root: Field,
    new_state_root: Field,
    nullifiers_batch_hash: Field,
    note_hashes_batch_hash: Field,
    deposit_nullifiers_hash: Field,
    withdrawal_claims_hash: Field,
    private_logs_hash: Field,
    nullifier_tree_start_index: Field,
    note_hash_tree_start_index: Field,
    // Caller-supplied expected commit over the four per-tx VK hashes.
    // We recompute and assert equality so the value is bound by circuit logic,
    // not just carried as an opaque witness.
    per_tx_vk_hashes_commit: Field,
) -> return_data BatchOutput {
    // 0. Boundary sanity.
    assert(
        deposit_count + payment_count + withdraw_count <= MAX_BATCH_SIZE,
        "section counts exceed batch size",
    );

    let pay_start = deposit_count;
    let wit_start = deposit_count + payment_count;
    let pad_start = deposit_count + payment_count + withdraw_count;

    // 1. Old state root consistency.
    assert(
        compute_state_root(old_nullifier_tree_root, old_note_hash_tree_root) == old_state_root,
        "old state root mismatch",
    );

    // Accumulators.
    let mut nullifiers: [Field; BATCH_NULLIFIERS_COUNT] = [0; BATCH_NULLIFIERS_COUNT];
    let mut note_hashes: [Field; BATCH_NOTE_HASHES_COUNT] = [0; BATCH_NOTE_HASHES_COUNT];
    let mut deposit_nullifiers: [Field; MAX_BATCH_SIZE] = [0; MAX_BATCH_SIZE];
    let mut withdrawal_claims: [Field; MAX_BATCH_SIZE] = [0; MAX_BATCH_SIZE];

    // Running tree roots.
    let mut cur_null_root = old_nullifier_tree_root;
    let mut cur_nh_root = old_note_hash_tree_root;
    let mut null_idx = nullifier_tree_start_index;
    let mut nh_idx = note_hash_tree_start_index;

    // 2. Process each slot.
    for i in 0..MAX_BATCH_SIZE {
        // --- Select VK for this slot based on section boundaries ---
        let is_deposit  = (i as u32) <  pay_start;
        let is_payment  = ((i as u32) >= pay_start) & ((i as u32) < wit_start);
        let is_withdraw = ((i as u32) >= wit_start) & ((i as u32) < pad_start);

        let selected_vk = if is_deposit {
            deposit_vk
        } else if is_payment {
            payment_vk
        } else if is_withdraw {
            withdraw_vk
        } else {
            padding_vk
        };

        let selected_vk_hash = if is_deposit {
            deposit_vk_hash
        } else if is_payment {
            payment_vk_hash
        } else if is_withdraw {
            withdraw_vk_hash
        } else {
            padding_vk_hash
        };

        // --- Verify proof against structurally-selected VK ---
        verify_honk_proof(
            selected_vk,
            tx_proofs[i],
            tx_public_inputs[i],
            selected_vk_hash,
        );

        let is_real = is_deposit | is_payment | is_withdraw;

        if is_real {
            // --- State binding ---
            let expected_state = compute_state_root(cur_null_root, cur_nh_root);
            assert(
                tx_public_inputs[i][4] == expected_state,
                "tx state root does not match running state",
            );

            // --- Insert nullifiers (indexed tree) ---
            for j in 0..MAX_NOTES_PER_TX {
                let null_val = tx_public_inputs[i][j];
                let sib_idx = i * MAX_NOTES_PER_TX + j;

                if null_val != 0 {
                    let low = nullifier_low_leaves[sib_idx];
                    let low_idx = nullifier_low_leaf_indices[sib_idx];
                    let low_sibs = nullifier_low_leaf_siblings[sib_idx];
                    let new_sibs = nullifier_new_leaf_siblings[sib_idx];

                    // a. Verify low_leaf exists in the current tree.
                    assert(
                        compute_merkle_root(low.hash(), low_idx, low_sibs) == cur_null_root,
                        "indexed insert: low leaf membership failed",
                    );

                    // b. Sandwich: low.value < null_val < low.next_value
                    //    (or low.next_value == 0 meaning tail of list).
                    assert(
                        low.value.lt(null_val),
                        "indexed insert: low leaf value not less than nullifier",
                    );
                    if low.next_value != 0 {
                        assert(
                            null_val.lt(low.next_value),
                            "indexed insert: nullifier not less than next value",
                        );
                    }

                    // c. Update low_leaf: point it to the new leaf.
                    let updated_low = IndexedLeaf {
                        value: low.value,
                        next_index: null_idx,
                        next_value: null_val,
                    };
                    let intermediate_root = compute_merkle_root(
                        updated_low.hash(),
                        low_idx,
                        low_sibs,
                    );

                    // d. Insert new leaf at the next sequential index.
                    let new_leaf = IndexedLeaf {
                        value: null_val,
                        next_index: low.next_index,
                        next_value: low.next_value,
                    };

                    // Verify the slot is empty (hash == 0) in the intermediate tree.
                    assert(
                        compute_merkle_root(0, null_idx, new_sibs) == intermediate_root,
                        "indexed insert: new leaf slot not empty",
                    );

                    // Compute the new root after inserting the new leaf.
                    cur_null_root = compute_merkle_root(
                        new_leaf.hash(),
                        null_idx,
                        new_sibs,
                    );
                    null_idx += 1;
                }

                nullifiers[i * MAX_NOTES_PER_TX + j] = null_val;
            }

            // --- Insert note hashes (append-only tree, unchanged) ---
            for j in 0..MAX_OUTPUTS_PER_TX {
                let nh_val = tx_public_inputs[i][MAX_NOTES_PER_TX + j];
                let sib_idx = i * MAX_OUTPUTS_PER_TX + j;

                if nh_val != 0 {
                    assert(
                        compute_merkle_root(0, nh_idx, note_hash_insertion_siblings[sib_idx])
                            == cur_nh_root,
                        "note hash insertion: slot not empty",
                    );
                    cur_nh_root = compute_merkle_root(
                        nh_val,
                        nh_idx,
                        note_hash_insertion_siblings[sib_idx],
                    );
                    nh_idx += 1;
                }

                note_hashes[i * MAX_OUTPUTS_PER_TX + j] = nh_val;
            }
        }

        // --- Route deposit / withdrawal metadata (structural) ---
        if is_deposit {
            deposit_nullifiers[i] = tx_public_inputs[i][0];
        }
        if is_withdraw {
            withdrawal_claims[i] = tx_public_inputs[i][MAX_NOTES_PER_TX];
        }

        // --- Log aggregation ---
        // Re-hash the wallet-supplied per-tx log payload and assert it matches
        // the logs_commit public input of tx i. Uniform across real + padding
        // slots so every batch has a well-defined log commitment.
        assert(
            poseidon2_hash(private_logs[i]) == tx_public_inputs[i][TX_LOGS_COMMIT_INDEX],
            "per-tx logs commit mismatch",
        );
    }

    // 3. Final tree roots.
    assert(cur_null_root == new_nullifier_tree_root, "nullifier tree root mismatch");
    assert(cur_nh_root == new_note_hash_tree_root, "note hash tree root mismatch");

    // 4. New state root consistency.
    assert(
        compute_state_root(new_nullifier_tree_root, new_note_hash_tree_root) == new_state_root,
        "new state root mismatch",
    );

    // 5. Batch commitment hashes.
    assert(
        poseidon2_hash(nullifiers) == nullifiers_batch_hash,
        "nullifiers batch hash mismatch",
    );
    assert(
        poseidon2_hash(note_hashes) == note_hashes_batch_hash,
        "note hashes batch hash mismatch",
    );
    assert(
        poseidon2_hash(deposit_nullifiers) == deposit_nullifiers_hash,
        "deposit nullifiers hash mismatch",
    );
    assert(
        poseidon2_hash(withdrawal_claims) == withdrawal_claims_hash,
        "withdrawal claims hash mismatch",
    );

    // Flatten all tx log payloads into a single batch-wide array and hash.
    let mut logs_flat: [Field; BATCH_LOGS_FLAT_LEN] = [0; BATCH_LOGS_FLAT_LEN];
    for i in 0..MAX_BATCH_SIZE {
        for j in 0..TX_LOG_PAYLOAD_LEN {
            logs_flat[i * TX_LOG_PAYLOAD_LEN + j] = private_logs[i][j];
        }
    }
    assert(
        poseidon2_hash(logs_flat) == private_logs_hash,
        "private logs batch hash mismatch",
    );

    // 6. Per-tx VK hashes commit.
    //    Binds the four private VK hashes verified above into a single value
    //    that propagates through the pipeline to the contract, which pins it
    //    at deployment. Prevents custom-circuit substitution in any tx slot.
    let computed_commit = compute_per_tx_vk_hashes_commit(
        deposit_vk_hash,
        payment_vk_hash,
        withdraw_vk_hash,
        padding_vk_hash,
    );
    assert(
        computed_commit == per_tx_vk_hashes_commit,
        "per-tx VK hashes commit mismatch",
    );

    BatchOutput {
        old_state_root,
        new_state_root,
        nullifiers_root: nullifiers_batch_hash,
        note_hashes_root: note_hashes_batch_hash,
        deposit_nullifiers_hash,
        withdrawal_claims_hash,
        private_logs_hash,
        nullifier_tree_start_index: nullifier_tree_start_index,
        note_hash_tree_start_index: note_hash_tree_start_index,
        per_tx_vk_hashes_commit,
    }
}
