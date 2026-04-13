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

    // Merged-batch sizes for pair_wrapper aggregated proofs (2 sub-batches).
    global MERGED_BATCH_SIZE: u32 = 16;
    global MERGED_BATCH_NULLIFIERS_COUNT: u32 = 32;
    global MERGED_BATCH_NOTE_HASHES_COUNT: u32 = 32;

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    #[storage]
    struct Storage<Context> {
        latest_root: PublicMutable<Field, Context>,
        // Both VK hashes are immutable (set once at deploy) so that private
        // functions can read them directly to bind verify_honk_proof's vk_hash
        // argument to the contract-committed circuit.
        //   - tube_vk_hash: the wrapper VK hash (used by submit_batch);
        //     name kept for ABI parity with contract_ivc.
        //   - merged_vk_hash: the pair_wrapper VK hash (used by submit_merged_batch).
        tube_vk_hash: PublicImmutable<Field, Context>,
        merged_vk_hash: PublicImmutable<Field, Context>,
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
        merged_vk_hash: Field,
    ) {
        self.storage.latest_root.write(initial_state_root);
        self.storage.tube_vk_hash.initialize(tube_vk_hash);
        self.storage.merged_vk_hash.initialize(merged_vk_hash);
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
    // submit_batch  (private)  -- permissionless
    //
    // `tube_vk` / `tube_proof` are the wrapper UltraHonk VK and proof in the
    // recursive pipeline. Names retained for cross-contract symmetry with the
    // IVC variant.
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
        // Bind the VK to the contract's committed wrapper vk hash (stored
        // under the tube_vk_hash slot name for cross-contract ABI parity).
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

        // Only forward what settle_batch needs for public state mutations.
        // All other verification (VK hash, batch hashes, tree indices) is
        // guaranteed by the kernel proof -- see DESIGN_DECISIONS.md.
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
    // settle_batch  (public, internal)
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
    // submit_merged_batch  (private)  -- recursive-aggregated 2-batch settlement
    //
    // Verifies ONE pair_wrapper UltraHonk proof that attests to the combined
    // state transition of TWO sub-batches (16 txs of slot capacity), then
    // enqueues ONE settle_batch_merged public call that advances state once.
    //
    // Contrast with L3IvcSettlement::submit_two_batches (IVC variant):
    //   - Meta path: 2 proofs in 1 L2 tx, 2 settles, nonce += 2.
    //   - Merged path: 1 proof in 1 L2 tx, 1 settle, nonce += 1.
    //
    // Public-input layout of the pair_wrapper proof mirrors BatchOutput but
    // the batch-commitment hashes are over MERGED (concatenated) arrays.
    // -----------------------------------------------------------------------

    #[external("private")]
    fn submit_merged_batch(
        merged_vk: UltraHonkVerificationKey,
        merged_proof: UltraHonkZKProof,
        public_inputs: [Field; BATCH_OUTPUT_FIELDS],
        merged_vk_hash: Field,
        nullifiers: [Field; MERGED_BATCH_NULLIFIERS_COUNT],
        note_hashes: [Field; MERGED_BATCH_NOTE_HASHES_COUNT],
        deposit_nullifiers: [Field; MERGED_BATCH_SIZE],
        withdrawal_claims: [Field; MERGED_BATCH_SIZE],
    ) {
        // Bind the VK to the contract's committed pair_wrapper vk hash.
        assert(
            merged_vk_hash == self.storage.merged_vk_hash.read(),
            "submit_merged_batch: merged_vk_hash does not match contract's committed hash",
        );
        verify_honk_proof(merged_vk, merged_proof, public_inputs, merged_vk_hash);

        // Count non-zero entries for tree index advancement.
        let mut null_count: Field = 0;
        for i in 0..MERGED_BATCH_NULLIFIERS_COUNT {
            if nullifiers[i] != 0 { null_count += 1; }
        }
        let mut nh_count: Field = 0;
        for i in 0..MERGED_BATCH_NOTE_HASHES_COUNT {
            if note_hashes[i] != 0 { nh_count += 1; }
        }

        self.enqueue_self.settle_batch_merged(
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
    // settle_batch_merged  (public, internal) -- batch=16 array sizing
    // -----------------------------------------------------------------------

    #[external("public")]
    #[only_self]
    fn settle_batch_merged(
        old_state_root: Field,
        new_state_root: Field,
        deposit_nullifiers: [Field; MERGED_BATCH_SIZE],
        withdrawal_claims: [Field; MERGED_BATCH_SIZE],
        null_count: Field,
        nh_count: Field,
        nullifiers: [Field; MERGED_BATCH_NULLIFIERS_COUNT],
        note_hashes: [Field; MERGED_BATCH_NOTE_HASHES_COUNT],
    ) {
        // 1. State chain check.
        assert(
            self.storage.latest_root.read() == old_state_root,
            "old state root mismatch",
        );

        // 2. Consume pending deposits (16 slots).
        for i in 0..MERGED_BATCH_SIZE {
            if deposit_nullifiers[i] != 0 {
                assert(
                    self.storage.pending_deposits.at(deposit_nullifiers[i]).read(),
                    "deposit not in pending list",
                );
                self.storage.pending_deposits.at(deposit_nullifiers[i]).write(false);
            }
        }

        // 3. Register pending withdrawals (16 slots).
        for i in 0..MERGED_BATCH_SIZE {
            if withdrawal_claims[i] != 0 {
                self.storage.pending_withdrawals.at(withdrawal_claims[i]).write(true);
            }
        }

        // 4. Advance state ONCE (single state transition for the whole merged batch).
        self.storage.latest_root.write(new_state_root);
        self.storage.batch_nonce.write(self.storage.batch_nonce.read() + 1);
        self.storage.nullifier_tree_start_index.write(
            self.storage.nullifier_tree_start_index.read() + null_count,
        );
        self.storage.note_hash_tree_start_index.write(
            self.storage.note_hash_tree_start_index.read() + nh_count,
        );

        // DA-available via the public function arguments: nullifiers, note_hashes,
        // deposit_nullifiers, withdrawal_claims (all batch=16 sized). No logs.
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
        // 1. Recompute the claim hash from the revealed preimage.
        let secret = poseidon2_hash([recipient.to_field(), salt]);
        let expected = poseidon2_hash([l2_token_address.to_field(), amount, secret]);
        assert(expected == claim_hash, "claim hash mismatch");

        // 2. Consume.
        assert(
            self.storage.pending_withdrawals.at(claim_hash).read(),
            "withdrawal not pending",
        );
        self.storage.pending_withdrawals.at(claim_hash).write(false);

        // 3. Transfer L2 tokens from this contract's public balance to the
        //    recipient. No authwit needed -- the contract is the `from`.
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
