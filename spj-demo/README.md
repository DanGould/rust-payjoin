# spj-demo

A recorded, human-legible demonstration of static payjoin on regtest.

A static payjoin endpoint is one payment string a receiver publishes once and is
paid over many times, by many senders, without any two payments sharing an
on-chain address and without the receiver being online when a payment starts.
Each scene exercises one property end to end against a real `bitcoind` regtest
node and the real mailroom directory service, and prints a narrated account with
a property claim and a verdict.

## Run

From the payjoin dev shell (provides `bitcoind` via `BITCOIND_EXE`):

```sh
nix develop -c cargo run -p spj-demo
```

Or record a full run into replayable artifacts:

```sh
nix develop -c ./spj-demo/run.sh
```

## Artifacts

`run.sh` writes to `spj-demo/artifacts/`:

- `transcript.txt` — the narrated run, plain text. The most quotable form.
- `session.log` + `session.timing` — a terminal capture. Replay it at the
  original pace:

  ```sh
  scriptreplay -t spj-demo/artifacts/session.timing spj-demo/artifacts/session.log
  ```

- `ledgers.md` — the cost accounting tables (spam gauntlet, fallback notice,
  lazy audit) as standalone markdown.
- `tweak-index.bin` — the toy tweak index scene 7 emits and audits.

Regtest keys and txids differ every run, so the artifacts are a snapshot of one
run, not byte-reproducible.

## Scenes

1. **Static reuse without address reuse** — one string paid three times by two
   senders lands on three distinct taproot outputs; a receiver restored from seed
   recovers every coin (payjoin outputs by wallet rescan, an unclaimed fallback
   by silent payment scan).
2. **Async first contact via the board** — a sender posts while the receiver is
   offline; the receiver starts later, finds its one notification among decoys,
   and completes. The directory's whole view is printed.
3. **The floor** — the receiver never returns; the sender's patience elapses and
   it broadcasts the original, a plain silent payment. No payment is lost.
4. **Token upgrade** — the mailroom starts requiring queue tokens; a returning
   sender presents one minted by the receiver's mailbox key and reaches the
   queue directly, while un-tokened posts and token replays are refused.
5. **The spam gauntlet** — one attacker-versus-receiver ledger per spam class.
6. **The fallback notice** — a sender out of patience broadcasts the original
   and posts the same signed transaction back to the queue; the receiver
   detects the settled payment from its mailbox alone, scanning zero chain
   transactions, and rejects a well-formed notice that pays anyone else.
7. **Lazy audit from a tweak index** — a sender holding only the bare address
   pays on chain; a receiver restored from seed finds the payment from a flat
   tweak index at one ECDH per eligible transaction and fetches exactly one
   block to claim it. Mainnet economics are quoted from published benchmarks,
   not demonstrated.

Two further scenes run outside the recorded harness; see
[`local-zk-scene.md`](local-zk-scene.md): key separation, and board admission by
a Curve Trees membership credential.

## What is real and what is a stub

- Real: the mailroom directory (queues, board, proof-of-work admission, queue
  token admission with replay dedupe), all OHTTP encapsulation and padding, the
  static session client, on-chain construction, broadcast, and confirmation.
- Stub, documented as such in the code and narration: silent payment derivation
  is done directly with secp256k1 group operations for one output per
  transaction (`src/sp.rs`), the scene 7 tweak index is a purpose-built toy in
  the record shape deployed tweak servers use (`src/index.rs`), and the scene 4
  queue token rides into the sender's post through the demo transport, because
  the stock sender cannot attach one yet. The mailroom's verification of that
  token is the production code path.

The directory runs in process as a `tower` service, so every wire byte crosses
the real gateway code without binding a port.
