use crate::L3IvcSettlement;
use aztec::{
    protocol::{address::AztecAddress, hash::poseidon2_hash, traits::ToField},
    test::helpers::test_environment::TestEnvironment,
};
use token::Token;

pub global TOKEN_NAME: str<31> = "TestToken0000000000000000000000";
pub global TOKEN_SYMBOL: str<31> = "TT00000000000000000000000000000";
pub global TOKEN_DECIMALS: u8 = 18;
pub global INITIAL_SUPPLY: u128 = 1_000_000;

// IVC pipeline batch sizes for test arrays. Keep in sync with main.nr globals.
pub global MAX_BATCH_SIZE: u32 = 8;
pub global BATCH_NULLIFIERS_COUNT: u32 = 16;
pub global BATCH_NOTE_HASHES_COUNT: u32 = 16;

// -----------------------------------------------------------------------
// TestL3 -- wraps contract interaction for clean multi-step tests.
//
// Tracks running state root and tree indices so each settle_batch call
// chains correctly. Uses synthetic roots (the contract trusts the proof;
// we bypass it by calling settle_batch as the contract itself).
// -----------------------------------------------------------------------

pub struct TestL3 {
    pub env: TestEnvironment,
    pub l3: AztecAddress,
    pub token: AztecAddress,
    pub admin: AztecAddress,
    pub state_root: Field,
    pub null_idx: Field, // next nullifier tree insertion index
    pub nh_idx: Field,   // next note hash tree insertion index
}

impl TestL3 {
    // Deploy Token + L3IvcSettlement and return a ready-to-use test handle.
    pub unconstrained fn setup() -> TestL3 {
        let mut env = TestEnvironment::new();
        let admin = env.create_light_account();

        // Deploy Token (sandbox token: constructor(admin, name, symbol, decimals)).
        let token_init = Token::interface().constructor(
            admin, TOKEN_NAME, TOKEN_SYMBOL, TOKEN_DECIMALS,
        );
        let token = env.deploy("@token_contract/Token").with_public_initializer(admin, token_init);

        // Mint public supply.
        env.call_public(admin, Token::at(token).mint_to_public(admin, INITIAL_SUPPLY));

        // Deploy L3IvcSettlement (zero genesis root, zero tube VK hash).
        let l3_init = L3IvcSettlement::interface().constructor(0, 0);
        let l3 = env.deploy("L3IvcSettlement").with_public_initializer(admin, l3_init);

        // Fund L3 contract with tokens for withdrawal payouts.
        env.call_public(admin, Token::at(token).mint_to_public(l3, INITIAL_SUPPLY));

        TestL3 {
            env, l3, token, admin,
            state_root: 0,
            null_idx: 1,  // genesis zero leaf at index 0
            nh_idx: 0,
        }
    }

    // Register a pending deposit (returns the deposit_hash).
    pub unconstrained fn register_deposit(&mut self, deposit_hash: Field) {
        self.env.call_public(
            self.l3,
            L3IvcSettlement::at(self.l3).register_deposit_internal(deposit_hash),
        );
    }

    // Settle a batch containing deposits, transfers, and/or withdrawals.
    //
    // - deposit_nullifiers: non-zero entries are deposit hashes to consume
    // - nullifiers: all 16 nullifiers (deposits + payments + withdrawals)
    // - note_hashes: all 16 note hashes
    // - withdrawal_claims: non-zero entries are claim hashes to register
    // - new_state_root: the synthetic post-batch root
    //
    // Automatically computes poseidon2 hashes, chains from current state,
    // and advances internal tracking.
    pub unconstrained fn settle(
        &mut self,
        nullifiers: [Field; BATCH_NULLIFIERS_COUNT],
        note_hashes: [Field; BATCH_NOTE_HASHES_COUNT],
        deposit_nullifiers: [Field; MAX_BATCH_SIZE],
        withdrawal_claims: [Field; MAX_BATCH_SIZE],
        new_state_root: Field,
    ) {
        // Count insertions for tree index advancement.
        let mut null_count: Field = 0;
        for i in 0..BATCH_NULLIFIERS_COUNT {
            if nullifiers[i] != 0 { null_count += 1; }
        }
        let mut nh_count: Field = 0;
        for i in 0..BATCH_NOTE_HASHES_COUNT {
            if note_hashes[i] != 0 { nh_count += 1; }
        }

        self.env.call_public(
            self.l3,
            L3IvcSettlement::at(self.l3).settle_batch(
                self.state_root,     // old_state_root
                new_state_root,
                deposit_nullifiers,
                withdrawal_claims,
                null_count,
                nh_count,
                nullifiers,
                note_hashes,
            ),
        );

        self.state_root = new_state_root;
        self.null_idx += null_count;
        self.nh_idx += nh_count;
    }

    // Claim a withdrawal (public token transfer to recipient).
    pub unconstrained fn claim_withdrawal(
        &mut self,
        recipient: AztecAddress,
        amount: Field,
        salt: Field,
    ) {
        let secret = poseidon2_hash([recipient.to_field(), salt]);
        let claim_hash = poseidon2_hash([self.token.to_field(), amount, secret]);

        self.env.call_public(
            recipient,
            L3IvcSettlement::at(self.l3).claim_withdrawal(
                self.token, amount, recipient, salt, claim_hash,
            ),
        );
    }

    // Read the contract's latest root.
    pub unconstrained fn latest_root(self) -> Field {
        self.env.view_public(L3IvcSettlement::at(self.l3).get_latest_root())
    }

    // Read the contract's batch nonce.
    pub unconstrained fn batch_nonce(self) -> Field {
        self.env.view_public(L3IvcSettlement::at(self.l3).get_batch_nonce())
    }

    // Read a public token balance.
    pub unconstrained fn token_balance(self, account: AztecAddress) -> u128 {
        self.env.view_public(Token::at(self.token).balance_of_public(account))
    }

    // Helper: compute a claim hash from components.
    pub fn compute_claim_hash(token: AztecAddress, amount: Field, recipient: AztecAddress, salt: Field) -> Field {
        let secret = poseidon2_hash([recipient.to_field(), salt]);
        poseidon2_hash([token.to_field(), amount, secret])
    }
}
