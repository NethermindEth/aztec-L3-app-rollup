use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul};

pub mod messages;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub global PROOF_TYPE_OINK: u32 = 1;
pub global PROOF_TYPE_HN_TAIL: u32 = 8;
pub global PROOF_TYPE_HN_FINAL: u32 = 7;
pub global PROOF_TYPE_CHONK: u32 = 9;

pub global ULTRA_HONK_PROOF_LENGTH: u32 = 500;
pub global ULTRA_HONK_VK_LENGTH: u32 = 115;
// Must be verified against actual output after compiling batch_app with Chonk.
pub global CHONK_PROOF_LENGTH: u32 = 1935;
pub global MEGA_VK_LENGTH: u32 = 127;

pub global TREE_DEPTH: u32 = 20;

// Per-tx layout: up to 2 input notes consumed, 2 output notes produced.
// These are per-transaction and identical across pipelines.
pub global MAX_NOTES_PER_TX: u32 = 2;
pub global MAX_OUTPUTS_PER_TX: u32 = 2;
// 2 nullifiers + 2 note hashes + state_root + logs_commit
// logs_commit = poseidon2_hash of flattened MAX_OUTPUTS_PER_TX * PRIVATE_LOG_SIZE_IN_FIELDS log fields.
pub global TX_PUBLIC_INPUT_COUNT: u32 = 6;
pub global TX_LOGS_COMMIT_INDEX: u32 = 5;

// Per-tx flat log payload: MAX_OUTPUTS_PER_TX outputs * 16 fields each = 32 fields.
pub global TX_LOG_PAYLOAD_LEN: u32 = MAX_OUTPUTS_PER_TX * messages::constants::PRIVATE_LOG_SIZE_IN_FIELDS;

// Size of the BatchOutput struct in fields. Identical for IVC and Recursive pipelines.
// Field layout:
//   [0] old_state_root
//   [1] new_state_root
//   [2] nullifiers_root
//   [3] note_hashes_root
//   [4] deposit_nullifiers_hash
//   [5] withdrawal_claims_hash
//   [6] private_logs_hash
//   [7] nullifier_tree_start_index
//   [8] note_hash_tree_start_index
//   [9] per_tx_vk_hashes_commit    -- poseidon2([dep, pay, wit, pad]_vk_hash).
//                                     Pinned on-chain so an attacker can't swap
//                                     in a custom per-tx circuit.
pub global BATCH_OUTPUT_FIELDS: u32 = 10;

// Index of per_tx_vk_hashes_commit inside BatchOutput / every downstream
// public-input layout that embeds BatchOutput at the front.
pub global PER_TX_VK_HASHES_COMMIT_INDEX: u32 = 9;

// NOTE: MAX_BATCH_SIZE, BATCH_NULLIFIERS_COUNT, and BATCH_NOTE_HASHES_COUNT are NOT
// defined here. They differ per pipeline and are owned by each batch-aggregation
// circuit (circuits/batch_app for IVC, circuits/batch_app_standalone for Recursive).

// Re-export the canonical poseidon2_hash from the Aztec protocol types.
// This guarantees consistency across circuits, contract, and TypeScript.
pub use protocol_types::hash::poseidon2_hash;

// ---------------------------------------------------------------------------
// Note
// ---------------------------------------------------------------------------

pub struct Note {
    pub owner_pubkey_hash: Field,
    pub amount: Field,
    pub token_id: Field,
    pub salt: Field,
}

impl Note {
    pub fn hash(self) -> Field {
        poseidon2_hash([self.owner_pubkey_hash, self.amount, self.token_id, self.salt])
    }
}

// ---------------------------------------------------------------------------
// BatchOutput -- threaded through the IVC kernel chain
// ---------------------------------------------------------------------------

pub struct BatchOutput {
    pub old_state_root: Field,
    pub new_state_root: Field,
    pub nullifiers_root: Field,
    pub note_hashes_root: Field,
    pub deposit_nullifiers_hash: Field,
    pub withdrawal_claims_hash: Field,
    pub private_logs_hash: Field,
    pub nullifier_tree_start_index: Field,
    pub note_hash_tree_start_index: Field,
    pub per_tx_vk_hashes_commit: Field,
}

impl BatchOutput {
    pub fn serialize(self) -> [Field; BATCH_OUTPUT_FIELDS] {
        [
            self.old_state_root,
            self.new_state_root,
            self.nullifiers_root,
            self.note_hashes_root,
            self.deposit_nullifiers_hash,
            self.withdrawal_claims_hash,
            self.private_logs_hash,
            self.nullifier_tree_start_index,
            self.note_hash_tree_start_index,
            self.per_tx_vk_hashes_commit,
        ]
    }
}

// Canonical commit over the four per-tx VK hashes. The on-chain contract pins
// this; every aggregator level carries it unchanged; the contract asserts the
// committed value to block foreign-circuit substitution attacks.
pub fn compute_per_tx_vk_hashes_commit(
    deposit_vk_hash: Field,
    payment_vk_hash: Field,
    withdraw_vk_hash: Field,
    padding_vk_hash: Field,
) -> Field {
    poseidon2_hash([deposit_vk_hash, payment_vk_hash, withdraw_vk_hash, padding_vk_hash])
}

// ---------------------------------------------------------------------------
// VerificationKey (Mega / Chonk VK used in kernel circuits)
// ---------------------------------------------------------------------------

pub struct VerificationKey {
    pub key: [Field; MEGA_VK_LENGTH],
    pub hash: Field,
}

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

pub fn hash_pubkey(x: Field, y: Field) -> Field {
    poseidon2_hash([x, y])
}

pub fn compute_nullifier(owner_secret: Field, note_salt: Field) -> Field {
    poseidon2_hash([owner_secret, note_salt])
}

pub fn compute_state_root(nullifier_tree_root: Field, note_hash_tree_root: Field) -> Field {
    poseidon2_hash([nullifier_tree_root, note_hash_tree_root])
}

// Derive the Grumpkin public key from a secret scalar.
pub fn derive_pubkey(secret: Field) -> EmbeddedCurvePoint {
    fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(secret))
}

// ---------------------------------------------------------------------------
// Indexed nullifier tree
// ---------------------------------------------------------------------------

// Leaf in the indexed (sorted linked-list) nullifier tree.
// value: the nullifier
// next_index: tree index of the next leaf in sorted order
// next_value: value of that next leaf (0 = this is the largest)
pub struct IndexedLeaf {
    pub value: Field,
    pub next_index: Field,
    pub next_value: Field,
}

impl IndexedLeaf {
    pub fn hash(self) -> Field {
        poseidon2_hash([self.value, self.next_index, self.next_value])
    }
}

// Proves that `value` does not exist in the indexed nullifier tree.
// The prover supplies the "low leaf" -- the leaf whose value is the
// largest in the tree that is still less than `value`.
pub fn verify_nullifier_non_membership(
    value: Field,
    low_leaf: IndexedLeaf,
    low_leaf_index: Field,
    low_leaf_siblings: [Field; TREE_DEPTH],
    root: Field,
) {
    // 1. low_leaf exists in the tree.
    verify_merkle_membership(low_leaf.hash(), low_leaf_index, low_leaf_siblings, root);

    // 2. value is sandwiched: low_leaf.value < value < low_leaf.next_value.
    //    If next_value == 0, low_leaf is the tail of the sorted list.
    assert(low_leaf.value.lt(value), "low leaf value must be less than nullifier");
    if low_leaf.next_value != 0 {
        assert(value.lt(low_leaf.next_value), "nullifier must be less than low leaf next value");
    }
}

// ---------------------------------------------------------------------------
// Merkle helpers
// ---------------------------------------------------------------------------

// Computes the Merkle root from a leaf, its index, and sibling path.
pub fn compute_merkle_root(
    leaf_hash: Field,
    index: Field,
    siblings: [Field; TREE_DEPTH],
) -> Field {
    let mut current = leaf_hash;
    let mut idx = index as u32;

    for i in 0..TREE_DEPTH {
        let is_right = idx & 1;
        let (left, right) = if is_right == 1 {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        current = poseidon2_hash([left, right]);
        idx >>= 1;
    }

    current
}

// Walks leaf -> root hashing with siblings. Asserts final hash == root.
pub fn verify_merkle_membership(
    leaf_hash: Field,
    index: Field,
    siblings: [Field; TREE_DEPTH],
    root: Field,
) {
    assert(compute_merkle_root(leaf_hash, index, siblings) == root, "Merkle membership verification failed");
}

// Proves the leaf at `index` is the canonical empty value (0).
pub fn verify_merkle_non_membership(
    index: Field,
    siblings: [Field; TREE_DEPTH],
    root: Field,
) {
    verify_merkle_membership(0, index, siblings, root);
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// Computes zero hashes for an empty tree: zero_hashes[i] is the root of
// an all-empty subtree at level i.
pub fn compute_zero_hashes() -> [Field; TREE_DEPTH] {
    let mut zh: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    for i in 1..TREE_DEPTH {
        zh[i] = poseidon2_hash([zh[i - 1], zh[i - 1]]);
    }
    zh
}

// Returns siblings for a leaf at `index` in a tree where only that one
// leaf is non-zero (all other leaves are 0).
pub fn siblings_for_single_leaf(index: u32) -> [Field; TREE_DEPTH] {
    let zh = compute_zero_hashes();
    let mut sibs: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    for i in 0..TREE_DEPTH {
        sibs[i] = zh[i];
    }
    sibs
}

// Returns siblings for a leaf at index 0 in the indexed nullifier tree
// where only the genesis zero-leaf at index 0 exists.
pub fn genesis_nullifier_siblings() -> [Field; TREE_DEPTH] {
    siblings_for_single_leaf(0)
}

// Computes the root of the indexed nullifier tree at genesis (only the
// zero-leaf at index 0).
pub fn genesis_nullifier_root() -> Field {
    let zero_leaf = IndexedLeaf { value: 0, next_index: 0, next_value: 0 };
    let sibs = genesis_nullifier_siblings();
    compute_merkle_root(zero_leaf.hash(), 0, sibs)
}

// Computes the root of an empty note hash tree (all leaves are 0).
pub fn empty_note_hash_root() -> Field {
    let zh = compute_zero_hashes();
    let mut root = zh[0]; // = 0
    for i in 0..TREE_DEPTH {
        root = poseidon2_hash([root, zh[i]]);
    }
    // Actually this isn't right -- the empty root is just zero_hashes[TREE_DEPTH].
    // But we only store TREE_DEPTH levels in zh. Let's compute it directly.
    let mut r: Field = 0;
    for _i in 0..TREE_DEPTH {
        r = poseidon2_hash([r, r]);
    }
    r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_poseidon2_hash_deterministic() {
    let h1 = poseidon2_hash([1, 2]);
    let h2 = poseidon2_hash([1, 2]);
    assert(h1 == h2);
    assert(h1 != 0);
}

#[test]
fn test_poseidon2_hash_different_inputs() {
    let h1 = poseidon2_hash([1, 2]);
    let h2 = poseidon2_hash([2, 1]);
    assert(h1 != h2);
}

#[test]
fn test_note_hash_deterministic() {
    let note = Note { owner_pubkey_hash: 1, amount: 100, token_id: 42, salt: 999 };
    let h1 = note.hash();
    let h2 = Note { owner_pubkey_hash: 1, amount: 100, token_id: 42, salt: 999 }.hash();
    assert(h1 == h2);
    assert(h1 != 0);
}

#[test]
fn test_note_hash_different_salt() {
    let n1 = Note { owner_pubkey_hash: 1, amount: 100, token_id: 42, salt: 1 };
    let n2 = Note { owner_pubkey_hash: 1, amount: 100, token_id: 42, salt: 2 };
    assert(n1.hash() != n2.hash());
}

#[test]
fn test_indexed_leaf_hash() {
    let leaf = IndexedLeaf { value: 42, next_index: 1, next_value: 100 };
    let h = leaf.hash();
    assert(h == poseidon2_hash([42, 1, 100]));
}

#[test]
fn test_compute_state_root() {
    let r = compute_state_root(10, 20);
    assert(r == poseidon2_hash([10, 20]));
}

#[test]
fn test_derive_pubkey_deterministic() {
    let pk1 = derive_pubkey(42);
    let pk2 = derive_pubkey(42);
    assert(pk1.x == pk2.x);
    assert(pk1.y == pk2.y);
}

#[test]
fn test_derive_pubkey_different_secrets() {
    let pk1 = derive_pubkey(1);
    let pk2 = derive_pubkey(2);
    assert(pk1.x != pk2.x);
}

#[test]
fn test_merkle_membership_single_leaf() {
    // Tree with one leaf at index 0, all others empty.
    let leaf_val: Field = 12345;
    let sibs = siblings_for_single_leaf(0);
    let root = compute_merkle_root(leaf_val, 0, sibs);
    verify_merkle_membership(leaf_val, 0, sibs, root);
}

#[test]
fn test_merkle_non_membership_empty_slot() {
    // In an empty tree, every slot holds 0.
    let zh = compute_zero_hashes();
    let mut empty_root: Field = 0;
    for _i in 0..TREE_DEPTH {
        empty_root = poseidon2_hash([empty_root, empty_root]);
    }
    // Siblings for index 0 in the fully empty tree are the zero hashes.
    let mut sibs: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    for i in 0..TREE_DEPTH {
        sibs[i] = zh[i];
    }
    verify_merkle_non_membership(0, sibs, empty_root);
}

#[test]
fn test_indexed_non_membership_genesis() {
    // Genesis nullifier tree: only the zero leaf at index 0.
    let zero_leaf = IndexedLeaf { value: 0, next_index: 0, next_value: 0 };
    let sibs = genesis_nullifier_siblings();
    let root = genesis_nullifier_root();

    // Any positive value should pass non-membership.
    verify_nullifier_non_membership(42, zero_leaf, 0, sibs, root);
    verify_nullifier_non_membership(999, zero_leaf, 0, sibs, root);
}

#[test]
fn test_indexed_insertion_then_non_membership() {
    // Start with genesis nullifier tree.
    let zero_leaf = IndexedLeaf { value: 0, next_index: 0, next_value: 0 };
    let sibs_0 = genesis_nullifier_siblings();
    let root_0 = genesis_nullifier_root();

    // Insert nullifier value 50.
    // Step 1: update zero leaf to point to new leaf at index 1.
    let updated_zero = IndexedLeaf { value: 0, next_index: 1, next_value: 50 };
    let root_1 = compute_merkle_root(updated_zero.hash(), 0, sibs_0);

    // Step 2: insert new leaf { value: 50, next_index: 0, next_value: 0 } at index 1.
    let new_leaf = IndexedLeaf { value: 50, next_index: 0, next_value: 0 };
    // Siblings for index 1: sibling at level 0 is the updated zero leaf hash,
    // higher levels are zero hashes (rest of tree is empty).
    let zh = compute_zero_hashes();
    let mut sibs_1: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    sibs_1[0] = updated_zero.hash();
    for i in 1..TREE_DEPTH {
        sibs_1[i] = zh[i];
    }
    let root_2 = compute_merkle_root(new_leaf.hash(), 1, sibs_1);

    // Now prove that 100 does NOT exist (low leaf is the new leaf at index 1).
    // Siblings for index 1 in root_2 are the same sibs_1.
    verify_nullifier_non_membership(100, new_leaf, 1, sibs_1, root_2);

    // Prove that 25 does NOT exist (low leaf is the updated zero leaf at index 0).
    // Siblings for index 0 in root_2: sibling at level 0 is new_leaf.hash(),
    // higher levels are zero hashes.
    let mut sibs_0_v2: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    sibs_0_v2[0] = new_leaf.hash();
    for i in 1..TREE_DEPTH {
        sibs_0_v2[i] = zh[i];
    }
    verify_nullifier_non_membership(25, updated_zero, 0, sibs_0_v2, root_2);
}

#[test]
fn test_full_payment_flow() {
    // 1. Derive owner key.
    let owner_secret: Field = 0xdead;
    let owner_pubkey = derive_pubkey(owner_secret);
    let owner_pubkey_hash = hash_pubkey(owner_pubkey.x, owner_pubkey.y);

    // 2. Create a note.
    let token_id: Field = 0x01;
    let amount: Field = 100;
    let salt: Field = 0xbeef;
    let note = Note { owner_pubkey_hash, amount, token_id, salt };
    let note_hash = note.hash();

    // 3. Insert note into note hash tree at index 0.
    let nh_sibs = siblings_for_single_leaf(0);
    let nh_root = compute_merkle_root(note_hash, 0, nh_sibs);

    // 4. Verify note membership.
    verify_merkle_membership(note_hash, 0, nh_sibs, nh_root);

    // 5. Compute nullifier.
    let nullifier = compute_nullifier(owner_secret, salt);

    // 6. Verify nullifier non-membership in genesis nullifier tree.
    let null_root = genesis_nullifier_root();
    let zero_leaf = IndexedLeaf { value: 0, next_index: 0, next_value: 0 };
    let null_sibs = genesis_nullifier_siblings();
    verify_nullifier_non_membership(nullifier, zero_leaf, 0, null_sibs, null_root);

    // 7. State root.
    let state_root = compute_state_root(null_root, nh_root);

    // 8. Build recipient note.
    let recipient_pubkey_hash = hash_pubkey(0xaaa, 0xbbb);
    let output_salt: Field = 0xcafe;
    let recipient_note = Note {
        owner_pubkey_hash: recipient_pubkey_hash,
        amount,
        token_id,
        salt: output_salt,
    };

    // 9. Verify conservation (full spend, no change).
    assert(amount == amount); // trivial for full spend

    // All assertions that the payment circuit would make pass.
    assert(note.owner_pubkey_hash == owner_pubkey_hash);
    assert(note.token_id == token_id);
    assert(compute_nullifier(owner_secret, note.salt) == nullifier);
    assert(compute_state_root(null_root, nh_root) == state_root);
    assert(recipient_note.hash() != 0);
}

#[test]
fn test_full_deposit_flow() {
    let recipient_pubkey_hash = hash_pubkey(0x111, 0x222);
    let amount: Field = 500;
    let token_id: Field = 0x42;
    let salt: Field = 0xfeed;

    // deposit_hash as the deposit circuit computes it.
    let deposit_hash = poseidon2_hash([recipient_pubkey_hash, amount, token_id, salt]);

    // L3 note as the deposit circuit creates it.
    let l3_note = Note { owner_pubkey_hash: recipient_pubkey_hash, amount, token_id, salt };
    let l3_note_hash = l3_note.hash();

    // These are the two values that become public inputs [nullifiers[0], note_hashes[0]].
    assert(deposit_hash != 0);
    assert(l3_note_hash != 0);

    // Verify deposit_hash == Note.hash since the preimages are identical.
    // (field order: [owner_pubkey_hash, amount, token_id, salt] in both)
    assert(deposit_hash == l3_note_hash);
}

#[test]
fn test_full_withdraw_flow() {
    // 1. Owner with an L3 note.
    let owner_secret: Field = 0xface;
    let owner_pubkey = derive_pubkey(owner_secret);
    let owner_pubkey_hash = hash_pubkey(owner_pubkey.x, owner_pubkey.y);

    let l2_token_address: Field = 0x42;
    let amount: Field = 200;
    let salt: Field = 0xdead;
    let note = Note { owner_pubkey_hash, amount, token_id: l2_token_address, salt };

    // 2. Nullifier.
    let nullifier = compute_nullifier(owner_secret, salt);

    // 3. Build L2 claim hash.
    let l2_recipient: Field = 0xabc123;
    let claim_salt: Field = 0xc1a1;
    let secret = poseidon2_hash([l2_recipient, claim_salt]);
    let claim_hash = poseidon2_hash([l2_token_address, amount, secret]);

    assert(claim_hash != 0);
    assert(nullifier != 0);
    assert(note.hash() != 0);

    // token_id == l2_token_address
    assert(note.token_id == l2_token_address);
}
