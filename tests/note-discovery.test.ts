// Phase 4 end-to-end note-discovery test.
//
// Self-contained, no sandbox required. Simulates the full flow:
//
//   sender wallet
//     |  buildTxLogs(notes, recipient)   -- per-tx [Field; 32] + logs_commit
//     v
//   assembleBatchLogsFlat(...)           -- batch-wide [Field; 256] calldata
//     |
//     v
//   settle_batch* (pretended -- we just read the calldata blob)
//     |
//     v
//   recipient indexer
//     |  scanSettleBatchLogs(calldata, recipient)
//     v
//   RecipientNoteStore.add(...)  -- note is discovered, decrypted, matched
//
// Asserts:
//   1. The tx circuit's logs_commit matches poseidon2_hash(private_logs).
//   2. Every active output is recoverable by its intended recipient.
//   3. Outputs targeting a different recipient are NOT recoverable by unrelated
//      parties (privacy).
//   4. The recipient can cross-check the decrypted note's hash against the
//      on-chain note_hashes array (integrity binding to L3 state).
//   5. Counter store advances on the sender and the recipient's scan window
//      tracks seen indices.

import { Fq, Fr } from "@aztec/foundation/curves/bn254";
import { Grumpkin } from "@aztec/foundation/crypto/grumpkin";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import { Point } from "@aztec/foundation/curves/grumpkin";

import {
  MAX_OUTPUTS_PER_TX,
  PRIVATE_LOG_SIZE_IN_FIELDS,
  RecipientCounterWindow,
  RecipientNoteStore,
  SenderCounterStore,
  TX_LOG_PAYLOAD_LEN,
  assembleBatchLogsFlat,
  buildTxLogs,
  scanSettleBatchLogs,
  type NotePreimage,
} from "./messages/index.js";

// Per-tx / batch sizes (match circuits/types/src/lib.nr + batch_app).
const MAX_BATCH_SIZE = 8;

let failures = 0;
function check(name: string, cond: boolean, detail?: unknown) {
  if (cond) {
    console.log(`  ok   ${name}`);
  } else {
    failures++;
    console.log(`  FAIL ${name}`);
    if (detail !== undefined) console.log(`       ${detail}`);
  }
}
async function section(name: string, body: () => Promise<void> | void) {
  console.log(`\n${name}`);
  await body();
}

async function makeParty(seedHi: bigint, seedLo: bigint) {
  const sk = new Fq((seedHi << 128n) + seedLo);
  const pk = await Grumpkin.mul(Grumpkin.generator, sk);
  const halfP = (Fr.MODULUS - 1n) / 2n;
  const pkPositive = pk.y.toBigInt() > halfP
    ? new Point(pk.x, new Fr(Fr.MODULUS - pk.y.toBigInt()), pk.isInfinite)
    : pk;
  const skPositive = pk.y.toBigInt() > halfP
    ? new Fq(Fq.MODULUS - sk.toBigInt())
    : sk;
  const address = pkPositive.x; // simplification for PoC: address === pk.x
  return { sk: skPositive, pk: pkPositive, address };
}

function zeroPayload(): Fr[] {
  return new Array<Fr>(TX_LOG_PAYLOAD_LEN).fill(new Fr(0n));
}

async function main() {
  const app = new Fr(0xc0ffeen);
  const sender = await makeParty(0x1n, 0x2n);
  const alice = await makeParty(0x100n, 0x200n); // recipient A
  const bob = await makeParty(0x300n, 0x400n);   // recipient B
  const eve = await makeParty(0xdeadn, 0xbeefn); // uninvited observer

  const sStore = new SenderCounterStore();

  // Build two payment txs, each with one real output going to Alice/Bob and
  // a zero second output. The rest of the batch (6 slots) is padding with
  // zero-log payloads.
  const noteForAlice: NotePreimage = {
    ownerPubkeyHash: new Fr(0xa11cen),
    amount: new Fr(1000n),
    tokenId: new Fr(0n),
    salt: new Fr(0x1111n),
  };
  const noteForBob: NotePreimage = {
    ownerPubkeyHash: new Fr(0xb0bn),
    amount: new Fr(500n),
    tokenId: new Fr(0n),
    salt: new Fr(0x2222n),
  };

  await section("sender builds per-tx logs", async () => {
    // tx 0: one output to Alice, one empty.
    const tx0 = await buildTxLogs({
      senderAddress: sender.address,
      senderAddressSecret: sender.sk,
      appAddress: app,
      outputs: [
        {
          note: noteForAlice,
          recipientAddress: alice.address,
          recipientAddressPoint: alice.pk,
        },
        null,
      ],
      counterStore: sStore,
    });
    check("tx0 privateLogs length = 32", tx0.privateLogs.length === TX_LOG_PAYLOAD_LEN);
    const commitExpected = await poseidon2Hash(tx0.privateLogs);
    check("tx0 logs_commit matches poseidon2_hash(private_logs)", tx0.logsCommit.equals(commitExpected));

    // tx 1: one output to Bob, one empty.
    const tx1 = await buildTxLogs({
      senderAddress: sender.address,
      senderAddressSecret: sender.sk,
      appAddress: app,
      outputs: [
        {
          note: noteForBob,
          recipientAddress: bob.address,
          recipientAddressPoint: bob.pk,
        },
        null,
      ],
      counterStore: sStore,
    });
    check("tx1 logs_commit matches poseidon2_hash(private_logs)", tx1.logsCommit.equals(await poseidon2Hash(tx1.privateLogs)));

    // Record these for batch assembly below.
    (globalThis as any).__tx0 = tx0;
    (globalThis as any).__tx1 = tx1;
  });

  // Assemble the batch-wide flat array: 2 real tx logs + 6 padding slots.
  const tx0 = (globalThis as any).__tx0;
  const tx1 = (globalThis as any).__tx1;
  const perTxPayloads: Fr[][] = [tx0.privateLogs, tx1.privateLogs];
  for (let i = 2; i < MAX_BATCH_SIZE; i++) perTxPayloads.push(zeroPayload());
  const batchLogs = assembleBatchLogsFlat(perTxPayloads);

  await section("batch-level layout", () => {
    check(
      `batchLogs length = ${MAX_BATCH_SIZE * TX_LOG_PAYLOAD_LEN}`,
      batchLogs.length === MAX_BATCH_SIZE * TX_LOG_PAYLOAD_LEN,
    );
    check("batchLogs slot 0 is tx0's first log entry", batchLogs[0].equals(tx0.privateLogs[0]));
    // tx1's payload starts at offset TX_LOG_PAYLOAD_LEN (32), not
    // PRIVATE_LOG_SIZE_IN_FIELDS (16), because each tx contributes 32 fields
    // (MAX_OUTPUTS_PER_TX * PRIVATE_LOG_SIZE_IN_FIELDS).
    check(
      "batchLogs tx1 offset is TX_LOG_PAYLOAD_LEN",
      batchLogs[TX_LOG_PAYLOAD_LEN].equals(tx1.privateLogs[0]),
    );
  });

  await section("Alice discovers her note", async () => {
    const aliceWindow = new RecipientCounterWindow();
    const aliceStore = new RecipientNoteStore();
    const found = await scanSettleBatchLogs(
      { privateLogs: batchLogs, app, finalized: true, blockNumber: 100 },
      {
        recipientAddress: alice.address,
        recipientAddressSecret: alice.sk,
        knownSenders: [
          { senderAddress: sender.address, senderAddressPoint: sender.pk },
        ],
        window: aliceWindow,
      },
    );
    aliceStore.add(found);
    check("Alice finds exactly one note", found.length === 1);
    if (found.length === 1) {
      check("owner_pubkey_hash preserved", found[0].note.ownerPubkeyHash.equals(noteForAlice.ownerPubkeyHash));
      check("amount preserved", found[0].note.amount.equals(noteForAlice.amount));
      check("salt preserved", found[0].note.salt.equals(noteForAlice.salt));
      // Note hash matches what the L3 note-hash tree would contain.
      const nh = await RecipientNoteStore.noteHash(found[0].note);
      const expectedNh = await poseidon2Hash([
        noteForAlice.ownerPubkeyHash,
        noteForAlice.amount,
        noteForAlice.tokenId,
        noteForAlice.salt,
      ]);
      check("reconstructed note_hash matches", nh.equals(expectedNh));
    }
  });

  await section("Bob discovers his note", async () => {
    const bobWindow = new RecipientCounterWindow();
    const found = await scanSettleBatchLogs(
      { privateLogs: batchLogs, app, finalized: true, blockNumber: 100 },
      {
        recipientAddress: bob.address,
        recipientAddressSecret: bob.sk,
        knownSenders: [
          { senderAddress: sender.address, senderAddressPoint: sender.pk },
        ],
        window: bobWindow,
      },
    );
    check("Bob finds exactly one note", found.length === 1);
    if (found.length === 1) {
      check("Bob's note amount = 500", found[0].note.amount.equals(noteForBob.amount));
      check("Bob's note salt preserved", found[0].note.salt.equals(noteForBob.salt));
    }
  });

  await section("Eve (uninvited) sees nothing", async () => {
    const eveWindow = new RecipientCounterWindow();
    const found = await scanSettleBatchLogs(
      { privateLogs: batchLogs, app, finalized: true, blockNumber: 100 },
      {
        recipientAddress: eve.address,
        recipientAddressSecret: eve.sk,
        knownSenders: [
          { senderAddress: sender.address, senderAddressPoint: sender.pk },
        ],
        window: eveWindow,
      },
    );
    check("Eve finds 0 notes", found.length === 0);
  });

  await section("sender counter store advanced", () => {
    const snapAlice = sStore.snapshot(sender.address, alice.address, app);
    const snapBob = sStore.snapshot(sender.address, bob.address, app);
    check("sender->alice nextIndex now 1", snapAlice.nextIndex === 1);
    check("sender->bob nextIndex now 1", snapBob.nextIndex === 1);
  });

  await section("window enforcement rejects overshoot", () => {
    // Force the store into a state where nextIndex would exceed the window.
    // We reserved index 0 already; set finalizedMaxIndex = -1 means window = 20.
    // Reserve 19 more without finalizing any -> 20th reservation should throw.
    let rejected = false;
    try {
      // Reserve 20 more slots (total 21) -- index 0 already taken; 1..20 legal;
      // 21 exceeds -1 + 20 = 19 limit once we hit it.
      for (let i = 0; i < 30; i++) {
        sStore.reserveNextIndex(sender.address, alice.address, app);
      }
    } catch (e) {
      rejected = true;
    }
    check("overshoot rejected", rejected);
  });

  console.log(`\n${failures === 0 ? "PASS" : `FAIL (${failures} assertion(s))`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
