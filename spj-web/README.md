# Silent Payjoin demo

Silent payments and payjoin from one URI. This crate runs three wallets in a
browser on a regtest node: Bob's silent payment wallet, Alice's wallet with
payjoin and silent payments, and an exchange. They reach each other only
through a payjoin directory and OHTTP relay that run in the same process on
127.0.0.1. Nothing leaves the machine.

It is a prototype. Don't use it with real coins.

The design it follows is a draft and will change. The pieces are:

- `spj-crypto`: BIP 352 silent payments with labels, BIP 374 DLEQ proofs, and
  BIP 375 shares and proofs carried in PSBT inputs.
- `spj-demo`: the receiver and sender sides of a silent payjoin, and six scenes
  that run end to end on regtest and check each result.
- `spj-web`: the wallets above, with a page to drive them.

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
