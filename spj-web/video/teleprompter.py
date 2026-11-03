#!/usr/bin/env python3
"""Build teleprompter.html from narration.md.

    python3 -I teleprompter.py [OUT.html] [MARKS.json]

The page shows one segment at a time, records it from the microphone and saves
<id>.wav files that build.sh takes as its audio directory. Words the picture waits
on (record.mjs untilPhrase calls and the cards' data-at lines) are underlined,
since the recorder stops if one goes missing from narration.md.
Rerun after editing narration.md. MARKS.json, written by build.sh next to
the video, gives each segment's place in the last take, so the page can show
the picture for the segment being read. OUT.html defaults to
teleprompter.html in the current directory.
"""

import html
import json
import os
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))
video_dir = here


def norm(token):
    return re.sub(r"[^a-z0-9'-]", "", token.lower())


def segments(text):
    out = []
    for block in re.split(r"^## +", text, flags=re.M)[1:]:
        head, _, body = block.partition("\n")
        out.append({"id": head.strip(), "text": " ".join(body.split())})
    return out


def anchors():
    found = []
    rec = open(os.path.join(video_dir, "record.mjs")).read()
    for seg, phrase in re.findall(r'untilPhrase\("([^"]+)", "([^"]+)"\)', rec):
        found.append((seg, phrase))
    cards = os.path.join(video_dir, "cards")
    for name in sorted(os.listdir(cards)):
        if name.endswith(".html"):
            for phrase in re.findall(
                r'data-at="([^"]+)"', open(os.path.join(cards, name)).read()
            ):
                found.append((None, phrase))
    return found


def mark_up(seg, cues):
    tokens = seg["text"].split(" ")
    words = [norm(t) for t in tokens]
    hit = [False] * len(tokens)
    used = []
    for only, phrase in cues:
        if only and only != seg["id"]:
            continue
        want = phrase.lower().split()
        for i in range(len(words) - len(want) + 1):
            if words[i : i + len(want)] == want:
                for j in range(i, i + len(want)):
                    hit[j] = True
                used.append(phrase)
                break
    out, run = [], []
    for tok, h in zip(tokens + [""], hit + [False]):
        if h:
            run.append(html.escape(tok))
            continue
        if run:
            out.append('<span class="cue">' + " ".join(run) + "</span>")
            run = []
        if tok:
            out.append(html.escape(tok))
    return " ".join(out), sorted(set(used))


def main():
    narration = open(os.path.join(here, "narration.md")).read()
    segs = segments(narration)
    cues = anchors()
    marks = {}
    out = sys.argv[1] if len(sys.argv) > 1 else "teleprompter.html"
    marks_file = sys.argv[2] if len(sys.argv) > 2 else ""
    if marks_file and os.path.exists(marks_file):
        for m in json.load(open(marks_file))["marks"]:
            marks[m["id"]] = {"t": m["t"], "d": m["d"]}
    data = []
    for seg in segs:
        body, used = mark_up(seg, cues)
        data.append(
            {"id": seg["id"], "html": body, "cues": used, "mark": marks.get(seg["id"])}
        )
    missing = [p for only, p in cues if not any(p in d["cues"] for d in data)]
    if missing:
        sys.exit("cue phrases not found in narration.md: " + ", ".join(missing))
    page = open(os.path.join(here, "teleprompter.template.html")).read()
    segments_js = json.dumps(data, ensure_ascii=False)
    page = re.sub(r"/\*SEGMENTS\*/\s*\[\]", lambda _: segments_js, page, count=1)
    open(out, "w").write(page)
    print(
        f"{out}: {len(data)} segments, {sum(len(d['cues']) for d in data)} cue phrases"
    )


main()
