use ::aztec::macros::aztec;

#[aztec]
pub contract L3RecursiveSettlement {
    use aztec::{
        macros::{
            functions::{external, initializer, only_self, view},
            storage::storage,
        },
        protocol::{
            address::AztecAddress,
            hash::poseidon2_hash,
            traits::ToField,
        },
        state_vars::{Map, PublicImmutable, PublicMutable},
    };
    use bb_proof_verification::{verify_honk_proof, UltraHonkVerificationKey, UltraHonkZKProof};
    use token::Token;

    // Recursive pipeline sub-batch sizes. Must match circuits/batch_app_standalone.
    // The on-chain proof here is the wrapper UltraHonk proof (not the tube), but
    // the field name `tube_vk_hash` is kept for parity with the IVC storage layout
    // so indexers can share generic decoders.
    global MAX_BATCH_SIZE: u32 = 8;
    global BATCH_OUTPUT_FIELDS: u32 = 8;
    global BATCH_NULLIFIERS_COUNT: u32 = 16;  // MAX_BATCH_SIZE * 2
    global BATCH_NOTE_HASHES_COUNT: u32 = 16; // MAX_BATCH_SIZE * 2

    // 16-slot aggregated batch (wrapper_16 proof = pair-merge of 2 wrappers).
    // Accepted on-chain via submit_batch_16.
    // Public-inputs: 8 BatchOutput fields + 1 inner wrapper_vk_hash binding
    // that the contract asserts against its committed tube_vk_hash.
    global BATCH_16_SIZE: u32 = 16;
    global BATCH_16_NULLIFIERS_COUNT: u32 = 32;
    global BATCH_16_NOTE_HASHES_COUNT: u32 = 32;
    global PUB_COUNT_16: u32 = 9;

    // 64-slot aggregated batch (wrapper_64 proof = 3-level binary tree:
    // wrapper x8 -> wrapper_16 x4 -> wrapper_32 x2 -> wrapper_64 x1).
    // Accepted on-chain via submit_batch_64.
    // Public-inputs: 8 BatchOutput fields + 3 inner VK-hash bindings
    // (wrapper / wrapper_16 / wrapper_32), each asserted against the matching
    // committed hash.
    global BATCH_64_SIZE: u32 = 64;
    global BATCH_64_NULLIFIERS_COUNT: u32 = 128;
    global BATCH_64_NOTE_HASHES_COUNT: u32 = 128;
    global PUB_COUNT_64: u32 = 11;

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    #[storage]
    struct Storage<Context> {
        latest_root: PublicMutable<Field, Context>,
        // All VK hashes are immutable (set once at deploy). Each binds a
        // specific aggregation-tree level's VK; the submit_* private
        // functions assert incoming proofs against the committed values,
        // closing the inner-VK substitution class at every level.
        //   tube_vk_hash: wrapper VK (used by submit_batch). Name kept for
        //     ABI parity with contract_ivc.
        //   vk_hash_16:   wrapper_16 VK (used by submit_batch_16).
        //   vk_hash_32:   wrapper_32 VK (used only as an intermediate
        //     chain-binding check from submit_batch_64).
        //   vk_hash_64:   wrapper_64 VK (used by submit_batch_64).
        tube_vk_hash: PublicImmutable<Field, Context>,
        vk_hash_16: PublicImmutable<Field, Context>,
        vk_hash_32: PublicImmutable<Field, Context>,
        vk_hash_64: PublicImmutable<Field, Context>,
        batch_nonce: PublicMutable<Field, Context>,
        nullifier_tree_start_index: PublicMutable<Field, Context>,
        note_hash_tree_start_index: PublicMutable<Field, Context>,
        pending_deposits: Map<Field, PublicMutable<bool, Context>, Context>,
        pending_withdrawals: Map<Field, PublicMutable<bool, Context>, Context>,
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    #[external("public")]
    #[initializer]
    fn constructor(
        initial_state_root: Field,
        tube_vk_hash: Field,
        vk_hash_16: Field,
        vk_hash_32: Field,
        vk_hash_64: Field,
    ) {
        self.storage.latest_root.write(initial_state_root);
        self.storage.tube_vk_hash.initialize(tube_vk_hash);
        self.storage.vk_hash_16.initialize(vk_hash_16);
        self.storage.vk_hash_32.initialize(vk_hash_32);
        self.storage.vk_hash_64.initialize(vk_hash_64);
        self.storage.batch_nonce.write(0);
        // Nullifier tree index 0 is the genesis zero leaf, so insertions start at 1.
        self.storage.nullifier_tree_start_index.write(1);
        self.storage.note_hash_tree_start_index.write(0);
    }

    // -----------------------------------------------------------------------
    // deposit  (private)
    //   User transfers L2 tokens to this contract and registers a pending
    //   deposit for inclusion in a future L3 batch.
    //
    //   The caller must have created an authwit authorising this contract
    //   to call transfer_private_to_public on the token contract.
    // -----------------------------------------------------------------------

    #[external("private")]
    fn deposit(
        token: AztecAddress,
        amount: Field,
        l3_recipient_pubkey_x: Field,
        l3_recipient_pubkey_y: Field,
        deposit_salt: Field,
        nonce: Field,
    ) {
        let sender = self.context.maybe_msg_sender().unwrap();

        // 1. Lock L2 tokens: private balance of sender -> public balance of
        //    this contract. The authwit covers (sender, this, amount, nonce).
        Token::at(token)
            .transfer_to_public(sender, self.context.this_address(), amount as u128, nonce)
            .call(self.context);

        // 2. Compute deposit_hash -- same preimage the deposit circuit checks.
        let recipient_pubkey_hash = poseidon2_hash(
            [l3_recipient_pubkey_x, l3_recipient_pubkey_y],
        );
        let deposit_hash = poseidon2_hash(
            [recipient_pubkey_hash, amount, token.to_field(), deposit_salt],
        );

        // 3. Enqueue public registration.
        self.enqueue_self.register_deposit_internal(deposit_hash);
    }

    #[external("public")]
    #[only_self]
    fn register_deposit_internal(deposit_hash: Field) {
        assert(
            !self.storage.pending_deposits.at(deposit_hash).read(),
            "deposit already registered",
        );
        self.storage.pending_deposits.at(deposit_hash).write(true);
    }

    // -----------------------------------------------------------------------
    // submit_batch  (private)  -- permissionless  [8-slot / wrapper path]
    //
    // `tube_vk` / `tube_proof` are the wrapper UltraHonk VK and proof.
    // Names retained for cross-contract symmetry with the IVC variant.
    // -----------------------------------------------------------------------

    #[external("private")]
    fn submit_batch(
        tube_vk: UltraHonkVerificationKey,
        tube_proof: UltraHonkZKProof,
        public_inputs: [Field; BATCH_OUTPUT_FIELDS],
        tube_vk_hash: Field,
        nullifiers: [Field; BATCH_NULLIFIERS_COUNT],
        note_hashes: [Field; BATCH_NOTE_HASHES_COUNT],
        deposit_nullifiers: [Field; MAX_BATCH_SIZE],
        withdrawal_claims: [Field; MAX_BATCH_SIZE],
    ) {
        assert(
            tube_vk_hash == self.storage.tube_vk_hash.read(),
            "submit_batch: wrapper vk_hash does not match contract's committed hash",
        );
        verify_honk_proof(tube_vk, tube_proof, public_inputs, tube_vk_hash);

        // Count non-zero entries for tree index advancement.
        let mut null_count: Field = 0;
        for i in 0..BATCH_NULLIFIERS_COUNT {
            if nullifiers[i] != 0 { null_count += 1; }
        }
        let mut nh_count: Field = 0;
        for i in 0..BATCH_NOTE_HASHES_COUNT {
            if note_hashes[i] != 0 { nh_count += 1; }
        }

        self.enqueue_self.settle_batch(
            public_inputs[0], // old_state_root
            public_inputs[1], // new_state_root
            deposit_nullifiers,
            withdrawal_claims,
            null_count,
            nh_count,
            nullifiers,
            note_hashes,
        );
    }

    // -----------------------------------------------------------------------
    // settle_batch  (public, internal)  [8-slot array sizing]
    // -----------------------------------------------------------------------

    #[external("public")]
    #[only_self]
    fn settle_batch(
        old_state_root: Field,
        new_state_root: Field,
        deposit_nullifiers: [Field; MAX_BATCH_SIZE],
        withdrawal_claims: [Field; MAX_BATCH_SIZE],
        null_count: Field,
        nh_count: Field,
        nullifiers: [Field; BATCH_NULLIFIERS_COUNT],
        note_hashes: [Field; BATCH_NOTE_HASHES_COUNT],
    ) {
        // 1. State chain -- prevents stale/duplicate batch application.
        assert(
            self.storage.latest_root.read() == old_state_root,
            "old state root mismatch",
        );

        // 2. Consume pending deposits.
        for i in 0..MAX_BATCH_SIZE {
            if deposit_nullifiers[i] != 0 {
                assert(
                    self.storage.pending_deposits.at(deposit_nullifiers[i]).read(),
                    "deposit not in pending list",
                );
                self.storage.pending_deposits.at(deposit_nullifiers[i]).write(false);
            }
        }

        // 3. Register pending withdrawals for L2 claiming.
        for i in 0..MAX_BATCH_SIZE {
            if withdrawal_claims[i] != 0 {
                self.storage.pending_withdrawals.at(withdrawal_claims[i]).write(true);
            }
        }

        // 4. Advance state.
        self.storage.latest_root.write(new_state_root);
        self.storage.batch_nonce.write(self.storage.batch_nonce.read() + 1);
        self.storage.nullifier_tree_start_index.write(
            self.storage.nullifier_tree_start_index.read() + null_count,
        );
        self.storage.note_hash_tree_start_index.write(
            self.storage.note_hash_tree_start_index.read() + nh_count,
        );

        // All batch data (nullifiers, note_hashes, deposit_nullifiers,
        // withdrawal_claims) is DA-available via the public function arguments.
        // No logs emitted -- L3 indexers decode directly from calldata.
    }

    // -----------------------------------------------------------------------
    // submit_batch_16  (private)  -- 16-slot aggregated settlement
    //
    // Verifies ONE wrapper_16 UltraHonk proof attesting to the combined state
    // transition of TWO 8-slot sub-batches. Binds both the wrapper_16 VK and
    // the inner wrapper VK to the contract's committed hashes.
    //
    // Contrast with L3IvcSettlement::submit_two_batches (IVC variant):
    //   - Meta path:  2 proofs in 1 L2 tx, 2 settles, nonce += 2.
    //   - wrapper_16: 1 proof in 1 L2 tx, 1 settle, nonce += 1.
    // -----------------------------------------------------------------------

    #[external("private")]
    fn submit_batch_16(
        vk_16: UltraHonkVerificationKey,
        proof_16: UltraHonkZKProof,
        public_inputs: [Field; PUB_COUNT_16],
        vk_hash_16: Field,
        nullifiers: [Field; BATCH_16_NULLIFIERS_COUNT],
        note_hashes: [Field; BATCH_16_NOTE_HASHES_COUNT],
        deposit_nullifiers: [Field; BATCH_16_SIZE],
        withdrawal_claims: [Field; BATCH_16_SIZE],
    ) {
        // 1. Bind the outer (wrapper_16) VK to the contract's committed hash.
        assert(
            vk_hash_16 == self.storage.vk_hash_16.read(),
            "submit_batch_16: vk_hash_16 does not match contract's committed hash",
        );
        // 2. Bind the INNER wrapper VK as published by wrapper_16 at
        //    public_inputs[8]. Closes the inner-VK substitution gap.
        assert(
            public_inputs[8] == self.storage.tube_vk_hash.read(),
            "submit_batch_16: inner wrapper_vk_hash does not match committed tube_vk_hash",
        );
        verify_honk_proof(vk_16, proof_16, public_inputs, vk_hash_16);

        let mut null_count: Field = 0;
        for i in 0..BATCH_16_NULLIFIERS_COUNT {
            if nullifiers[i] != 0 { null_count += 1; }
        }
        let mut nh_count: Field = 0;
        for i in 0..BATCH_16_NOTE_HASHES_COUNT {
            if note_hashes[i] != 0 { nh_count += 1; }
        }

        self.enqueue_self.settle_batch_16(
            public_inputs[0], // old_state_root (A.old)
            public_inputs[1], // new_state_root (B.new)
            deposit_nullifiers,
            withdrawal_claims,
            null_count,
            nh_count,
            nullifiers,
            note_hashes,
        );
    }

    // -----------------------------------------------------------------------
    // settle_batch_16  (public, internal)  [16-slot array sizing]
    // -----------------------------------------------------------------------

    #[external("public")]
    #[only_self]
    fn settle_batch_16(
        old_state_root: Field,
        new_state_root: Field,
        deposit_nullifiers: [Field; BATCH_16_SIZE],
        withdrawal_claims: [Field; BATCH_16_SIZE],
        null_count: Field,
        nh_count: Field,
        nullifiers: [Field; BATCH_16_NULLIFIERS_COUNT],
        note_hashes: [Field; BATCH_16_NOTE_HASHES_COUNT],
    ) {
        assert(
            self.storage.latest_root.read() == old_state_root,
            "old state root mismatch",
        );

        for i in 0..BATCH_16_SIZE {
            if deposit_nullifiers[i] != 0 {
                assert(
                    self.storage.pending_deposits.at(deposit_nullifiers[i]).read(),
                    "deposit not in pending list",
                );
                self.storage.pending_deposits.at(deposit_nullifiers[i]).write(false);
            }
        }

        for i in 0..BATCH_16_SIZE {
            if withdrawal_claims[i] != 0 {
                self.storage.pending_withdrawals.at(withdrawal_claims[i]).write(true);
            }
        }

        // Advance state ONCE (single state transition for the whole 16-slot batch).
        self.storage.latest_root.write(new_state_root);
        self.storage.batch_nonce.write(self.storage.batch_nonce.read() + 1);
        self.storage.nullifier_tree_start_index.write(
            self.storage.nullifier_tree_start_index.read() + null_count,
        );
        self.storage.note_hash_tree_start_index.write(
            self.storage.note_hash_tree_start_index.read() + nh_count,
        );
    }

    // -----------------------------------------------------------------------
    // submit_batch_64  (private)  -- 64-slot aggregated settlement
    //
    // Verifies ONE wrapper_64 UltraHonk proof attesting to the combined state
    // transition of 8 sub-batches. Binds the full VK chain:
    //   public_inputs[8]  == tube_vk_hash   (wrapper)
    //   public_inputs[9]  == vk_hash_16     (wrapper_16)
    //   public_inputs[10] == vk_hash_32     (wrapper_32)
    // plus the outer wrapper_64 VK itself.
    //
    // NOTE on soundness: verify_honk_proof is a no-op under sandbox /
    // TestEnvironment ACIR simulation. The real proof gate only fires
    // against an Aztec node with real proving enabled. Local soundness for
    // this aggregation level is covered via external `bb verify` -- see
    // SILENT_FAILURE_REVIEW.md and tests/verify-with-bb-cli.ts.
    // -----------------------------------------------------------------------

    #[external("private")]
    fn submit_batch_64(
        vk_64: UltraHonkVerificationKey,
        proof_64: UltraHonkZKProof,
        public_inputs: [Field; PUB_COUNT_64],
        vk_hash_64: Field,
        nullifiers: [Field; BATCH_64_NULLIFIERS_COUNT],
        note_hashes: [Field; BATCH_64_NOTE_HASHES_COUNT],
        deposit_nullifiers: [Field; BATCH_64_SIZE],
        withdrawal_claims: [Field; BATCH_64_SIZE],
    ) {
        // Full VK chain binding.
        assert(
            vk_hash_64 == self.storage.vk_hash_64.read(),
            "submit_batch_64: vk_hash_64 does not match contract's committed hash",
        );
        assert(
            public_inputs[8] == self.storage.tube_vk_hash.read(),
            "submit_batch_64: inner wrapper_vk_hash does not match committed tube_vk_hash",
        );
        assert(
            public_inputs[9] == self.storage.vk_hash_16.read(),
            "submit_batch_64: inner vk_hash_16 does not match committed vk_hash_16",
        );
        assert(
            public_inputs[10] == self.storage.vk_hash_32.read(),
            "submit_batch_64: inner vk_hash_32 does not match committed vk_hash_32",
        );
        verify_honk_proof(vk_64, proof_64, public_inputs, vk_hash_64);

        let mut null_count: Field = 0;
        for i in 0..BATCH_64_NULLIFIERS_COUNT {
            if nullifiers[i] != 0 { null_count += 1; }
        }
        let mut nh_count: Field = 0;
        for i in 0..BATCH_64_NOTE_HASHES_COUNT {
            if note_hashes[i] != 0 { nh_count += 1; }
        }

        self.enqueue_self.settle_batch_64(
            public_inputs[0],
            public_inputs[1],
            deposit_nullifiers,
            withdrawal_claims,
            null_count,
            nh_count,
            nullifiers,
            note_hashes,
        );
    }

    // -----------------------------------------------------------------------
    // settle_batch_64  (public, internal)  [64-slot array sizing]
    // -----------------------------------------------------------------------

    #[external("public")]
    #[only_self]
    fn settle_batch_64(
        old_state_root: Field,
        new_state_root: Field,
        deposit_nullifiers: [Field; BATCH_64_SIZE],
        withdrawal_claims: [Field; BATCH_64_SIZE],
        null_count: Field,
        nh_count: Field,
        nullifiers: [Field; BATCH_64_NULLIFIERS_COUNT],
        note_hashes: [Field; BATCH_64_NOTE_HASHES_COUNT],
    ) {
        assert(
            self.storage.latest_root.read() == old_state_root,
            "old state root mismatch",
        );

        for i in 0..BATCH_64_SIZE {
            if deposit_nullifiers[i] != 0 {
                assert(
                    self.storage.pending_deposits.at(deposit_nullifiers[i]).read(),
                    "deposit not in pending list",
                );
                self.storage.pending_deposits.at(deposit_nullifiers[i]).write(false);
            }
        }

        for i in 0..BATCH_64_SIZE {
            if withdrawal_claims[i] != 0 {
                self.storage.pending_withdrawals.at(withdrawal_claims[i]).write(true);
            }
        }

        self.storage.latest_root.write(new_state_root);
        self.storage.batch_nonce.write(self.storage.batch_nonce.read() + 1);
        self.storage.nullifier_tree_start_index.write(
            self.storage.nullifier_tree_start_index.read() + null_count,
        );
        self.storage.note_hash_tree_start_index.write(
            self.storage.note_hash_tree_start_index.read() + nh_count,
        );
    }

    // -----------------------------------------------------------------------
    // claim_withdrawal  (public)
    //   Anyone can call -- tokens always go to the committed recipient.
    //   Front-run safe: the claim_hash binds to the recipient address via
    //   secret = poseidon2([recipient, salt]).
    // -----------------------------------------------------------------------

    #[external("public")]
    fn claim_withdrawal(
        l2_token_address: AztecAddress,
        amount: Field,
        recipient: AztecAddress,
        salt: Field,
        claim_hash: Field,
    ) {
        let secret = poseidon2_hash([recipient.to_field(), salt]);
        let expected = poseidon2_hash([l2_token_address.to_field(), amount, secret]);
        assert(expected == claim_hash, "claim hash mismatch");

        assert(
            self.storage.pending_withdrawals.at(claim_hash).read(),
            "withdrawal not pending",
        );
        self.storage.pending_withdrawals.at(claim_hash).write(false);

        Token::at(l2_token_address)
            .transfer_in_public(self.context.this_address(), recipient, amount as u128, 0)
            .call(self.context);
    }

    // -----------------------------------------------------------------------
    // Views
    // -----------------------------------------------------------------------

    #[external("public")]
    #[view]
    fn get_latest_root() -> Field {
        self.storage.latest_root.read()
    }

    #[external("public")]
    #[view]
    fn get_batch_nonce() -> Field {
        self.storage.batch_nonce.read()
    }
}

pub mod test;
