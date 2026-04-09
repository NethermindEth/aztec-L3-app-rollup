use ::aztec::macros::aztec;

#[aztec]
pub contract L3Settlement {
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
        state_vars::{Map, PublicMutable},
    };
    use bb_proof_verification::{verify_honk_proof, UltraHonkVerificationKey, UltraHonkZKProof};
    use token::Token;

    // NOTE: reduced to 4 for testing (Chonk ECCVM limit). See circuits/types/src/lib.nr.
    global MAX_BATCH_SIZE: u32 = 4;
    global BATCH_OUTPUT_FIELDS: u32 = 8;
    global BATCH_NULLIFIERS_COUNT: u32 = 8;
    global BATCH_NOTE_HASHES_COUNT: u32 = 8;

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    #[storage]
    struct Storage<Context> {
        latest_root: PublicMutable<Field, Context>,
        tube_vk_hash: PublicMutable<Field, Context>,
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
    fn constructor(initial_state_root: Field, tube_vk_hash: Field) {
        self.storage.latest_root.write(initial_state_root);
        self.storage.tube_vk_hash.write(tube_vk_hash);
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
        verify_honk_proof(tube_vk, tube_proof, public_inputs, tube_vk_hash);

        self.enqueue_self.settle_batch(
            tube_vk_hash,
            public_inputs[0], // old_state_root
            public_inputs[1], // new_state_root
            public_inputs[2], // nullifiers_batch_hash
            public_inputs[3], // note_hashes_batch_hash
            public_inputs[4], // deposit_nullifiers_hash
            public_inputs[5], // withdrawal_claims_hash
            public_inputs[6], // nullifier_tree_start_index
            public_inputs[7], // note_hash_tree_start_index
            nullifiers,
            note_hashes,
            deposit_nullifiers,
            withdrawal_claims,
        );
    }

    // -----------------------------------------------------------------------
    // settle_batch  (public, internal)
    // -----------------------------------------------------------------------

    #[external("public")]
    #[only_self]
    fn settle_batch(
        tube_vk_hash: Field,
        old_state_root: Field,
        new_state_root: Field,
        nullifiers_batch_hash: Field,
        note_hashes_batch_hash: Field,
        deposit_nullifiers_hash: Field,
        withdrawal_claims_hash: Field,
        nullifier_tree_start_index: Field,
        note_hash_tree_start_index: Field,
        nullifiers: [Field; BATCH_NULLIFIERS_COUNT],
        note_hashes: [Field; BATCH_NOTE_HASHES_COUNT],
        deposit_nullifiers: [Field; MAX_BATCH_SIZE],
        withdrawal_claims: [Field; MAX_BATCH_SIZE],
    ) {
        // 1. Tube VK.
        assert(
            tube_vk_hash == self.storage.tube_vk_hash.read(),
            "tube vk hash mismatch",
        );

        // 2. State chain.
        assert(
            self.storage.latest_root.read() == old_state_root,
            "old state root mismatch",
        );

        // 3. Tree indices must match stored next positions.
        assert(
            self.storage.nullifier_tree_start_index.read() == nullifier_tree_start_index,
            "nullifier tree start index mismatch",
        );
        assert(
            self.storage.note_hash_tree_start_index.read() == note_hash_tree_start_index,
            "note hash tree start index mismatch",
        );

        // 4. Verify all proof-committed hashes.
        assert(
            poseidon2_hash(nullifiers) == nullifiers_batch_hash,
            "nullifiers hash mismatch",
        );
        assert(
            poseidon2_hash(note_hashes) == note_hashes_batch_hash,
            "note hashes hash mismatch",
        );
        assert(
            poseidon2_hash(deposit_nullifiers) == deposit_nullifiers_hash,
            "deposit nullifiers hash mismatch",
        );
        assert(
            poseidon2_hash(withdrawal_claims) == withdrawal_claims_hash,
            "withdrawal claims hash mismatch",
        );

        // 5. Consume pending deposits.
        for i in 0..MAX_BATCH_SIZE {
            if deposit_nullifiers[i] != 0 {
                assert(
                    self.storage.pending_deposits.at(deposit_nullifiers[i]).read(),
                    "deposit not in pending list",
                );
                self.storage.pending_deposits.at(deposit_nullifiers[i]).write(false);
            }
        }

        // 6. Register pending withdrawals for L2 claiming.
        for i in 0..MAX_BATCH_SIZE {
            if withdrawal_claims[i] != 0 {
                self.storage.pending_withdrawals.at(withdrawal_claims[i]).write(true);
            }
        }

        // 7. Count non-zero insertions to advance indices.
        let mut null_count: Field = 0;
        for i in 0..BATCH_NULLIFIERS_COUNT {
            if nullifiers[i] != 0 { null_count += 1; }
        }
        let mut nh_count: Field = 0;
        for i in 0..BATCH_NOTE_HASHES_COUNT {
            if note_hashes[i] != 0 { nh_count += 1; }
        }

        // 8. Advance state.
        self.storage.latest_root.write(new_state_root);
        self.storage.batch_nonce.write(self.storage.batch_nonce.read() + 1);
        self.storage.nullifier_tree_start_index.write(nullifier_tree_start_index + null_count);
        self.storage.note_hash_tree_start_index.write(note_hash_tree_start_index + nh_count);

        // 9. Emit full arrays for DA / off-chain indexers.
        self.context.emit_public_log_unsafe(0, nullifiers);
        self.context.emit_public_log_unsafe(1, note_hashes);
        self.context.emit_public_log_unsafe(2, deposit_nullifiers);
        self.context.emit_public_log_unsafe(3, withdrawal_claims);
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
