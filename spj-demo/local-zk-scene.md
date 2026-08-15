# Local scenes: key separation and ZK-credential admission

Two demonstrations that do not run in the recorded harness. Scene 6 (key
separation) and the Curve Trees credential admission both need things the
recorded harness deliberately avoids: `aut-ct` pulls crates over the network
and runs a WebSocket daemon, and the credential keyset is built from a full
node's UTXO dump. Run these on a machine with network access and a regtest
`bitcoind`.

Everything below is regtest. The credential scene proves the _mechanism_
(one-show tags, epoch rollover, double-show rejection) and quotes mainnet
economics; regtest coins are free, so it does not and cannot demonstrate the
sybil capital wall.

---

## Scene 6 — key separation

**Property**: handing out the scan key never grants payjoin access. A watch-only
scanning service given `b_scan` (and the public spend key) finds fallback silent
payments on chain, but cannot decrypt a mailbox frame or answer a sender, because
the mailbox reply key is separate.

The demo already separates these keys:

- `b_scan` / `b_spend` — silent payment scan and spend keys (`spj-demo/src/sp.rs`,
  `SpKeys::from_seed`). Scanning needs `b_scan` plus the public spend key;
  spending needs `b_spend`.
- the static receiver's HPKE key — decrypts queue frames and authenticates
  replies (`StaticReceiverBuilder::new`'s fourth argument). Independent of both
  silent payment keys.

**Runbook**

1. Derive the three keys from one seed and print their public halves:

   ```sh
   # from the payjoin dev shell
   nix develop -c cargo run -p spj-demo --example keys -- --seed "<demo seed>"
   ```

   (Write this small example if you want it; the derivation is
   `SpKeys::from_seed` plus `HpkeKeyPair::gen_keypair`. It is not built into the
   recorded harness because scene 6 is a local scene.)

2. Stand up a watch-only scanner holding only `b_scan` and the public spend key.
   Point it at the regtest chain and confirm it finds the fallback outputs from
   the recorded run (the same outputs `scan_chain_for_sp` recovers in scene 1).

3. Confirm the scanner cannot:
   - decrypt a queue frame — it has no HPKE secret key; `decrypt_message_a`
     fails.
   - produce a valid reply — replies are authenticated by the receiver HPKE key
     it does not hold.

4. Verdict to record: a scan key outsourced to a third party reveals incoming
   payments to that party and nothing else. It cannot move funds, read a
   payment negotiation, or impersonate the receiver.

---

## Credential admission — Curve Trees membership via aut-ct

**Property**: board admission can be gated by a zero-knowledge proof that the
poster controls a taproot UTXO in a public filtered set, with a per-epoch
one-show tag, so no party ever holds a list of participating wallets. The
anonymity set is the entire filtered taproot UTXO set on every post.

This replaces the proof-of-work board admission (`payjoin-mailroom`'s
`PowAdmission`) with a verifier backed by `aut-ct`. The mailroom's `Admission`
trait is the seam: `verify` returns the public tag used for replay dedupe, which
maps onto aut-ct's key image.

### Upstream caveats (read before forking)

- **No LICENSE file** on `aut-ct` or `curve-trees` (readme-only MIT). Contact
  AdamISZ before any public fork or redistribution.
- **Experimental, benchmark-grade** code. Fine for a demo, not production.
- **Constant-J tag is unfixed upstream** (`src/utils.rs`, `J = H2C("J" ||
context_label)`). Related-key linkage applies: an adversary who knows the
  scalar delta between two of the poster's own credential coins (for instance a
  BIP352 sender who paid the poster twice) can link those two tags within an
  epoch. For the demo, rotate epochs by folding the epoch into `context_label`
  (the upstream-endorsed workaround) and disclose the exposure. Production fix is
  the DY-style tag `(sk + H(ctx))^{-1}·G` sketched in curve-trees `PRF.md`.
- **Sign-flip**: the verifier accepts ±D and returns a 33-byte key image on
  every terminal path. Canonicalize to even-Y before storing for dedupe, or rely
  solely on aut-ct's own per-context `KeyImageStore` (`.aki` files, reuse returns
  accepted = -3).

### Build the keyset (regtest)

```sh
# 1. Dump the regtest UTXO set from a synced regtest node
bitcoin-cli -regtest dumptxoutset /tmp/regtest-utxos.dat

# 2. Convert + filter to a taproot x-only keyset. aut-ct ships the recipe in
#    docs/utxo-keysets.md: utxo_dump_tools then filter_utxos.py with the
#    V_min / age filters you want to advertise as the anonymity set.
python3 filter_utxos.py --min-value 500000 --input /tmp/regtest-utxos.dat \
    --output regtest.aks
```

`.aks` is whitespace-separated 32-byte x-only hex on one line. On regtest the
set is small; generate several thousand qualifying taproot UTXOs from a separate
wallet first so the keyset is not operator theater.

### Run the verifier

```sh
# 3. Build aut-ct (network access required)
git clone https://github.com/AdamISZ/aut-ct && cd aut-ct
cargo build --release

# 4. Serve verification for a context label that encodes the epoch
./target/release/autct serve -k "spj-epoch-0:regtest.aks"
# WebSocket toy-rpc on ws://127.0.0.1:23333
# RPCProofVerifyRequest / RPCProofVerifyResponse; see docs/RPC-API.md
```

### Wire it into the mailroom

Implement an `Admission` whose `verify` forwards the submission's proof to the
`autct` verifier over the WebSocket RPC and, on success, returns the returned key
image as the replay tag; `seen` / `record_success` map to the per-epoch key-image
store. Swap it in where `PowAdmission` is constructed (`Board::new`'s admission
argument). The board route code does not change: it already treats admission as a
trait that yields a public dedupe tag.

### Scene to record

1. A poster with a qualifying regtest taproot UTXO proves membership; the board
   accepts. Show the proof size (~3-4 KB) and verify time (~40-60 ms).
2. The same coin proves again in the same epoch: same key image, rejected.
3. Roll the epoch (`context_label` changes): the same coin proves again and is
   accepted, demonstrating per-epoch allowance renewal, including a post that
   straddles the rollover.
4. A double-spend of the queue token is rejected;
   a proof replayed under a stale epoch is rejected.
5. Narrate the mainnet quote: on mainnet the set is ~238K taproot keys of at
   least 500K sats, reproduced by anyone with a node, held by no one. Regtest
   proves the mechanism; the capital wall is a mainnet property.

---

## Why these are not in the recorded harness

`aut-ct`'s build fetches crates from the network and its verifier is a listening
daemon. The recorded harness is self-contained by design: it fetches nothing and
starts no standalone daemons, running the directory in process instead. Build
and run these two scenes where a network fetch and a local daemon are allowed.
