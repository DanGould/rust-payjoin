#!/usr/bin/env python3
"""Transcribe a recorded read and show where it differs from narration.md.

    nix shell nixpkgs#whisper-cpp nixpkgs#ffmpeg --command \\
      python3 -I check-read.py MODEL.bin VO_DIR

MODEL.bin is a whisper.cpp model, for example ggml-medium.en.bin from
https://huggingface.co/ggerganov/whisper.cpp. VO_DIR holds one <id>.wav per
`## id` block. For each segment it prints the words that differ, so the
script can be brought in line with what was said: the subtitles are built
from the script, and the picture's cue phrases must appear in it.
Transcripts go to VO_DIR/transcripts.json.

Speech recognition mishears some words, so read a difference before taking
it: rerun one file with whisper-cli's -ml 1 to see per-word timing.
"""

import difflib
import json
import os
import re
import subprocess
import sys
import tempfile

here = os.path.dirname(os.path.abspath(__file__))
model, vo = sys.argv[1], sys.argv[2]
# Spelling hints for words a general English model gets wrong.
hint = "Silent Payjoin, payjoin, silent payments, URI, sats, Bob, Alice"


def words(s):
    out = []
    for w in s.replace("-", " ").split():
        w = re.sub(r"[^a-z0-9']", "", w.lower())
        if w:
            out.append(w)
    return out


segments = {}
text = open(os.path.join(here, "narration.md")).read()
for block in re.split(r"^## +", text, flags=re.M)[1:]:
    head, _, body = block.partition("\n")
    segments[head.strip()] = " ".join(body.split())

transcripts = {}
with tempfile.TemporaryDirectory() as tmp:
    pcm = os.path.join(tmp, "16k.wav")
    for sid, script in segments.items():
        wav = os.path.join(vo, sid + ".wav")
        if not os.path.exists(wav):
            print(f"## {sid}: no recording")
            continue
        # whisper.cpp reads 16 kHz mono.
        subprocess.run(
            [
                "ffmpeg",
                "-loglevel",
                "error",
                "-y",
                "-i",
                wav,
                "-ar",
                "16000",
                "-ac",
                "1",
                pcm,
            ],
            check=True,
        )
        said = subprocess.run(
            ["whisper-cli", "-m", model, "-f", pcm, "-nt", "-np", "--prompt", hint],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        said = " ".join(said.split())
        transcripts[sid] = said
        a, b = words(script), words(said)
        ops = [
            o
            for o in difflib.SequenceMatcher(None, a, b).get_opcodes()
            if o[0] != "equal"
        ]
        if not ops:
            print(f"## {sid}: same")
            continue
        print(f"## {sid}")
        for tag, i1, i2, j1, j2 in ops:
            print(
                f"   {tag:7} script: {' '.join(a[i1:i2]) or '-':40}  said: {' '.join(b[j1:j2]) or '-'}"
            )

with open(os.path.join(vo, "transcripts.json"), "w") as f:
    json.dump(transcripts, f, indent=1)
