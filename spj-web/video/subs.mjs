#!/usr/bin/env node
// Subtitles for a take, from its narration script and marks.
//
//   node subs.mjs NARRATION.md MARKS.json OUT.srt OUT.vtt
//
// Each `## id` block of the script is said from its mark for `d` seconds.
// The text is cut into cues of at most two lines of about 42 characters,
// at sentence ends where it can be, and each cue gets the share of the
// segment's time that its words have. A read keeps roughly even pace within
// a segment, so this follows any voice.

import fs from "node:fs";

const [narrationFile, marksFile, srtOut, vttOut] = process.argv.slice(2);
if (!vttOut) {
  console.error("usage: node subs.mjs NARRATION.md MARKS.json OUT.srt OUT.vtt");
  process.exit(2);
}
const LINE = 42;
// Silence the voice files end with (tts.py), not part of the read.
const TAIL = 0.25;

// Spoken forms that read better written out.
const WRITTEN = [[/payjoin dot org slash S P/gi, "payjoin.org/sp"]];

const script = fs.readFileSync(narrationFile, "utf8");
const blocks = new Map();
const parts = script.split(/^## +(\S+) *$/m);
for (let i = 1; i < parts.length; i += 2)
  blocks.set(parts[i], parts[i + 1].split(/\s+/).filter(Boolean).join(" "));
const { marks } = JSON.parse(fs.readFileSync(marksFile, "utf8"));

/** Break `text` into lines of at most LINE characters, as even as can be. */
function lines(text) {
  const words = text.split(" ");
  if (text.length <= LINE) return [text];
  let best = null;
  for (let i = 1; i < words.length; i++) {
    const a = words.slice(0, i).join(" ");
    const b = words.slice(i).join(" ");
    const worst = Math.max(a.length, b.length);
    if (!best || worst < best.worst) best = { worst, out: [a, b] };
  }
  return best.out;
}

/** Cut a sentence into pieces that fit two lines, at commas if possible. */
function pieces(sentence) {
  if (lines(sentence).every((l) => l.length <= LINE)) return [sentence];
  const words = sentence.split(" ");
  let best = null;
  for (let i = 1; i < words.length; i++) {
    const a = words.slice(0, i).join(" ");
    const b = words.slice(i).join(" ");
    // Prefer a cut after punctuation, then an even one.
    const score = Math.abs(a.length - b.length) - (/[,:;]$/.test(a) ? 1000 : 0);
    if (!best || score < best.score) best = { score, a, b };
  }
  return [...pieces(best.a), ...pieces(best.b)];
}

const cues = [];
for (const [i, mark] of marks.entries()) {
  const text = blocks.get(mark.id);
  if (!text) continue;
  const sentences = text.match(/[^.!?]+[.!?]+|[^.!?]+$/g).map((s) => s.trim());
  const chunks = sentences.flatMap(pieces);
  const count = (s) => s.split(" ").length;
  const total = chunks.reduce((n, c) => n + count(c), 0);
  const end = Math.min(
    mark.t + Math.max(mark.d - TAIL, 0.5),
    marks[i + 1]?.t ?? Infinity,
  );
  const span = end - mark.t;
  let done = 0;
  for (const chunk of chunks) {
    const start = mark.t + (span * done) / total;
    done += count(chunk);
    let written = chunk;
    for (const [from, to] of WRITTEN) written = written.replace(from, to);
    cues.push({
      start: Math.max(0, start),
      end: mark.t + (span * done) / total,
      lines: lines(written),
    });
  }
}

const stamp = (t, sep) => {
  const ms = Math.round(t * 1000);
  const h = Math.floor(ms / 3600000);
  const m = Math.floor(ms / 60000) % 60;
  const s = Math.floor(ms / 1000) % 60;
  const pad = (n, w = 2) => String(n).padStart(w, "0");
  return `${pad(h)}:${pad(m)}:${pad(s)}${sep}${pad(ms % 1000, 3)}`;
};
fs.writeFileSync(
  srtOut,
  cues
    .map(
      (c, i) =>
        `${i + 1}\n${stamp(c.start, ",")} --> ${stamp(c.end, ",")}\n${c.lines.join("\n")}\n`,
    )
    .join("\n"),
);
fs.writeFileSync(
  vttOut,
  `WEBVTT\n\n${cues
    .map(
      (c) =>
        `${stamp(c.start, ".")} --> ${stamp(c.end, ".")}\n${c.lines.join("\n")}\n`,
    )
    .join("\n")}`,
);
console.log(`${srtOut}, ${vttOut}: ${cues.length} cues`);
