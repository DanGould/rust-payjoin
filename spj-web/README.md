# Silent Payjoin

People who support both payjoin and silent payments want to compose them.
This is a prototype of how, on regtest only. Don't use it with real coins.

https://github.com/user-attachments/assets/abb2ab24-186a-43f4-a7d8-59b16401477e

One-time URIs should be the default. A one-time URI is an ordinary payjoin,
and the silent payment address in it says the receiver supports a contact.
A contact URI replaces that base silent payment address with a labelled one
and a reusable 1-to-1 mailbox. That's where a Silent Payjoin happens. The
receiver adds a coin, works out its output again, and attaches a proof the
payer checks before it signs.

Composing them for open donations makes little sense. There's no good
anonymous, permissionless, economical DoS limiter for a publicly known
mailbox, so a donation address stays a plain silent payment address.

This builds on Armin Sabouri's
[write-up on silent payjoins](https://github.com/payjoin/research-docs/tree/main/silent-payjoins)
from January 2026, which worked out the receiver's share of the tweak and
the DLEQ proof that lets the sender check it. The design here is a draft and
will change.

## The parts

| Crate                         | What it is                                                                                                                |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| [`spj-crypto`](../spj-crypto) | BIP 352 silent payments with labels, BIP 374 DLEQ proofs, and BIP 375 shares and proofs carried in PSBT inputs            |
| [`spj-demo`](../spj-demo)     | The receiver and sender sides of a Silent Payjoin, and six scenes that run end to end on regtest and check each result    |
| [`spj-web`](.)                | Three wallets in a browser (Bob, Alice and the exchange) with a page to drive them, and the script that records the video |

The wallets reach each other only through a payjoin directory and OHTTP relay
that run in the same process on 127.0.0.1. Nothing leaves the machine.

Specifications: [BIP 352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
silent payments, [BIP 374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
DLEQ proofs, [BIP 375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)
silent payments in PSBTs, [BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
async payjoin.

## Run it

From the repository root:

```sh
nix develop --command cargo run -p spj-web -- --port 8080
```

Then open http://127.0.0.1:8080. The dev shell provides `bitcoind`. The scenes
without a browser run with `cargo run -p spj-demo`.

## The video

`video/build.sh` records the video from a script and a folder of audio. It
starts the wallets, records one take in headless Chromium that waits on each
line of narration, then lays the audio and subtitles over it.

```sh
video/build.sh out/silent-payjoin-demo.mp4 video/narration.md <audio-dir>
```

`<audio-dir>` holds one `<id>.wav` per `## id` block of `video/narration.md`.
Two ways to get them:

- A synthetic voice: `python3 video/tts.py video/narration.md <audio-dir>`
  (Kokoro, see the top of `tts.py`).
- Your own voice: `python3 video/teleprompter.py` writes `teleprompter.html`.
  Open it in Chrome, press Space and read. Press → at the end of each line to
  save it and keep going, or R to read that line again. D downloads the lines
  as a zip.

If the read strays from the script, `video/check-read.py` transcribes each
line and shows what changed, so the script and subtitles can be brought in
line. The picture waits on a few exact words, which the teleprompter
underlines, so keep those as written or move the cue with them.
