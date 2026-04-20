import { Fr } from "@aztec/foundation/curves/bn254";

// Sender-indexed tagging counter store, mirroring aztec-packages v4.2
// yarn-project/pxe/src/tagging/{sender_sync,constants}.ts.
//
// Each (localAddress, externalAddress, app) key has a monotonically-increasing
// index used when the local party SENDS a message to the external party.
// Aztec enforces a sliding window: a new index cannot exceed
// `finalizedMax + UNFINALIZED_TAGGING_INDEXES_WINDOW_LEN` so the recipient's
// scan range stays bounded. We mirror that invariant.

export const UNFINALIZED_TAGGING_INDEXES_WINDOW_LEN = 20;

type Key = string;

function keyOf(local: Fr, external: Fr, app: Fr): Key {
  return `${local.toString()}|${external.toString()}|${app.toString()}`;
}

export interface CounterSnapshot {
  nextIndex: number;
  finalizedMaxIndex: number;
}

// In-memory counter store. Persistent state for long-running PXEs would back
// this with disk; in-memory is sufficient for PoC tests and deterministic
// scenario replay.
export class SenderCounterStore {
  private nextIndex = new Map<Key, number>();
  private finalizedMaxIndex = new Map<Key, number>();

  /** Reserve the next index for (local -> external) over `app`. Throws if the
   *  sliding window would be violated. Callers should pair this with actual
   *  log emission; a reserved index that is never emitted creates a gap that
   *  the recipient must still scan through (up to WINDOW_LEN). */
  reserveNextIndex(local: Fr, external: Fr, app: Fr): number {
    const k = keyOf(local, external, app);
    const nxt = this.nextIndex.get(k) ?? 0;
    const finMax = this.finalizedMaxIndex.get(k) ?? -1;
    if (nxt > finMax + UNFINALIZED_TAGGING_INDEXES_WINDOW_LEN) {
      throw new Error(
        `tagging index ${nxt} exceeds sliding-window bound (finalizedMax=${finMax}, window=${UNFINALIZED_TAGGING_INDEXES_WINDOW_LEN})`,
      );
    }
    this.nextIndex.set(k, nxt + 1);
    return nxt;
  }

  /** Record that the recipient has finalized messages up to `index` (inclusive)
   *  for this directional pair, freeing the sliding window to advance. */
  markFinalized(local: Fr, external: Fr, app: Fr, index: number): void {
    const k = keyOf(local, external, app);
    const prev = this.finalizedMaxIndex.get(k) ?? -1;
    if (index > prev) this.finalizedMaxIndex.set(k, index);
  }

  /** Peek the next index without reserving it. */
  peekNextIndex(local: Fr, external: Fr, app: Fr): number {
    return this.nextIndex.get(keyOf(local, external, app)) ?? 0;
  }

  snapshot(local: Fr, external: Fr, app: Fr): CounterSnapshot {
    const k = keyOf(local, external, app);
    return {
      nextIndex: this.nextIndex.get(k) ?? 0,
      finalizedMaxIndex: this.finalizedMaxIndex.get(k) ?? -1,
    };
  }
}

// Recipient-side tracker for the sliding scan window (agedMax, finalizedMax + WINDOW_LEN].
// Once an index observed in a finalized block lies more than MAX_TX_LIFETIME old, it
// becomes the new agedMax and can stop being scanned. For PoC we expose the primitives;
// a full implementation needs block-timestamp tracking.
export class RecipientCounterWindow {
  private highestFinalizedIndex = new Map<Key, number>();
  private highestAgedIndex = new Map<Key, number>();

  markSeen(local: Fr, external: Fr, app: Fr, index: number, finalized: boolean): void {
    const k = keyOf(local, external, app);
    if (finalized) {
      const prev = this.highestFinalizedIndex.get(k) ?? -1;
      if (index > prev) this.highestFinalizedIndex.set(k, index);
    }
  }

  markAged(local: Fr, external: Fr, app: Fr, index: number): void {
    const k = keyOf(local, external, app);
    const prev = this.highestAgedIndex.get(k) ?? -1;
    if (index > prev) this.highestAgedIndex.set(k, index);
  }

  /** The closed interval (agedMax, finalizedMax + WINDOW_LEN] to scan for this pair. */
  scanRange(local: Fr, external: Fr, app: Fr): { from: number; to: number } {
    const k = keyOf(local, external, app);
    const aged = this.highestAgedIndex.get(k) ?? -1;
    const fin = this.highestFinalizedIndex.get(k) ?? -1;
    return {
      from: aged + 1,
      to: fin + UNFINALIZED_TAGGING_INDEXES_WINDOW_LEN,
    };
  }
}
