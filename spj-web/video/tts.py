"""Voice a narration script with Kokoro-82M.

    python3 tts.py NARRATION.md OUT_DIR [--voice am_michael] [--speed 1.0] [--only ID ...]

NARRATION.md holds one block per segment: a `## id` line, then the text to
say. Each block becomes OUT_DIR/<id>.wav (24 kHz mono). A short silence is
kept at the end of each file so cuts never clip the last word.

Needs Python with the `kokoro` and `soundfile` packages, for example from
nixpkgs:

    nix shell --impure --expr \\
      '(import <nixpkgs> {}).python3.withPackages (ps: [ps.kokoro ps.soundfile])' \\
      --command python3 tts.py ...

The model weights come from Hugging Face (hexgrad/Kokoro-82M) on first use.
"""

import argparse
import pathlib
import re

import numpy as np
import soundfile as sf
from kokoro import KPipeline

RATE = 24000


def segments(text):
    """The (id, text) blocks of a narration script, in order."""
    blocks = re.split(r"^## +(\S+) *$", text, flags=re.M)
    out = []
    for i in range(1, len(blocks), 2):
        body = " ".join(blocks[i + 1].split())
        if body:
            out.append((blocks[i], body))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("narration")
    ap.add_argument("out")
    ap.add_argument("--voice", default="am_michael")
    ap.add_argument("--speed", type=float, default=1.0)
    ap.add_argument("--only", nargs="*")
    args = ap.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    pipeline = KPipeline(lang_code="a", repo_id="hexgrad/Kokoro-82M")
    for seg_id, text in segments(pathlib.Path(args.narration).read_text()):
        if args.only and seg_id not in args.only:
            continue
        # Kokoro splits on sentences; a short pause between them reads as a
        # person explaining rather than a run-on.
        pieces = []
        for _, _, audio in pipeline(
            text, voice=args.voice, speed=args.speed, split_pattern=r"(?<=[.!?])\s+"
        ):
            pieces.append(np.asarray(audio))
            pieces.append(np.zeros(int(RATE * 0.18), dtype=np.float32))
        pieces.append(np.zeros(int(RATE * 0.25), dtype=np.float32))
        audio = np.concatenate(pieces)
        sf.write(out / f"{seg_id}.wav", audio, RATE)
        print(f"{seg_id}: {len(audio) / RATE:.1f} s")


if __name__ == "__main__":
    main()
