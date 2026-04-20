use crate::messages::constants::{PRIVATE_LOG_CIPHERTEXT_LEN, PRIVATE_LOG_SIZE_IN_FIELDS};

/// On-chain private log, shaped to match aztec-packages' `PrivateLog` wire format.
///
/// Layout on the wire as a flat [Field; PRIVATE_LOG_SIZE_IN_FIELDS] array:
///   [ siloed_tag, ct_0, ct_1, ..., ct_{PRIVATE_LOG_CIPHERTEXT_LEN - 1} ]
///
/// In the ONCHAIN_UNCONSTRAINED delivery mode (the only mode Aztec ships today),
/// both the tag and the ciphertext are produced by the sender's wallet off-circuit
/// and handed to the L3 circuit as witness. The circuit does not verify that the
/// ciphertext decrypts to the note preimage -- a malicious sender can grief their
/// recipient (liveness), but cannot corrupt note state (safety holds via the
/// separate note-hash commitment). This matches Aztec's current production model.
pub struct PrivateLog {
    pub siloed_tag: Field,
    pub ciphertext: [Field; PRIVATE_LOG_CIPHERTEXT_LEN],
}

impl PrivateLog {
    /// Flatten to a [Field; 16] suitable for inclusion in circuit public inputs or
    /// for hashing into batch-level commitments.
    pub fn to_fields(self) -> [Field; PRIVATE_LOG_SIZE_IN_FIELDS] {
        let mut out: [Field; PRIVATE_LOG_SIZE_IN_FIELDS] = [0; PRIVATE_LOG_SIZE_IN_FIELDS];
        out[0] = self.siloed_tag;
        for i in 0..PRIVATE_LOG_CIPHERTEXT_LEN {
            out[i + 1] = self.ciphertext[i];
        }
        out
    }

    /// Inverse of `to_fields`. Accepts a flat array in wire layout.
    pub fn from_fields(fields: [Field; PRIVATE_LOG_SIZE_IN_FIELDS]) -> Self {
        let mut ct: [Field; PRIVATE_LOG_CIPHERTEXT_LEN] = [0; PRIVATE_LOG_CIPHERTEXT_LEN];
        for i in 0..PRIVATE_LOG_CIPHERTEXT_LEN {
            ct[i] = fields[i + 1];
        }
        Self { siloed_tag: fields[0], ciphertext: ct }
    }

    /// A zero log is used as a placeholder for inactive output slots so that the
    /// circuit's public-input layout remains fixed regardless of output count.
    /// Callers are responsible for ensuring the wallet does not publish these
    /// slots on-chain.
    pub fn zero() -> Self {
        Self { siloed_tag: 0, ciphertext: [0; PRIVATE_LOG_CIPHERTEXT_LEN] }
    }
}

#[test]
fn test_private_log_roundtrip() {
    let mut ct: [Field; PRIVATE_LOG_CIPHERTEXT_LEN] = [0; PRIVATE_LOG_CIPHERTEXT_LEN];
    for i in 0..PRIVATE_LOG_CIPHERTEXT_LEN {
        ct[i] = (i as Field) + 1;
    }
    let log = PrivateLog { siloed_tag: 42, ciphertext: ct };

    let fields = log.to_fields();
    assert(fields[0] == 42);
    assert(fields[1] == 1);
    assert(fields[PRIVATE_LOG_SIZE_IN_FIELDS - 1] == (PRIVATE_LOG_CIPHERTEXT_LEN as Field));

    let reconstructed = PrivateLog::from_fields(fields);
    assert(reconstructed.siloed_tag == log.siloed_tag);
    for i in 0..PRIVATE_LOG_CIPHERTEXT_LEN {
        assert(reconstructed.ciphertext[i] == log.ciphertext[i]);
    }
}

#[test]
fn test_private_log_zero() {
    let z = PrivateLog::zero();
    assert(z.siloed_tag == 0);
    for i in 0..PRIVATE_LOG_CIPHERTEXT_LEN {
        assert(z.ciphertext[i] == 0);
    }
}
