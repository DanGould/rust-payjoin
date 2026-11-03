#!/usr/bin/env node
// Lay the narration over a recorded take.
//
//   node mux.mjs TAKE.mp4 MARKS.json VO_DIR OUT.mp4 [SUBTITLES.srt]
//
// MARKS.json comes from record.mjs: when each segment starts in the take.
// Each `<id>.wav` in VO_DIR is placed at its segment's start. A segment
// with no file is left silent, and one that runs into the next is reported,
// since the take held only as long as the audio it was recorded with.
// SUBTITLES.srt goes in as a subtitle track a player can switch on; it is
// not shown unless asked for.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const [take, marksFile, voDir, out, subtitles] = process.argv.slice(2);
if (!out) {
  console.error(
    "usage: node mux.mjs TAKE.mp4 MARKS.json VO_DIR OUT.mp4 [SUBTITLES.srt]",
  );
  process.exit(2);
}
const { duration, marks } = JSON.parse(fs.readFileSync(marksFile, "utf8"));

const probe = (file) =>
  Number(
    execFileSync("ffprobe", [
      "-v",
      "error",
      "-show_entries",
      "format=duration",
      "-of",
      "csv=p=0",
      file,
    ])
      .toString()
      .trim(),
  );

const inputs = [];
for (const [i, mark] of marks.entries()) {
  const file = path.join(voDir, `${mark.id}.wav`);
  if (!fs.existsSync(file)) {
    console.warn(`no ${mark.id}.wav; that segment is silent`);
    continue;
  }
  const length = probe(file);
  const next = marks[i + 1]?.t ?? duration;
  if (mark.t + length > next + 0.05) {
    console.warn(
      `${mark.id}.wav (${length.toFixed(1)} s) runs ${(mark.t + length - next).toFixed(1)} s into the next segment; rebuild the take with this audio`,
    );
  }
  inputs.push({ file, at: mark.t });
}
if (!inputs.length) throw new Error(`no narration audio in ${voDir}`);

const args = ["-y", "-loglevel", "error", "-i", take];
for (const input of inputs) args.push("-i", input.file);
if (subtitles) args.push("-i", subtitles);
const delayed = inputs.map((input, i) => {
  const ms = Math.max(0, Math.round(input.at * 1000));
  return `[${i + 1}:a]aresample=48000,adelay=${ms}:all=1[a${i}]`;
});
const mix = `${inputs.map((_, i) => `[a${i}]`).join("")}amix=inputs=${inputs.length}:normalize=0:dropout_transition=0,apad,atrim=0:${duration}[aout]`;
args.push(
  "-filter_complex",
  [...delayed, mix].join(";"),
  "-map",
  "0:v",
  "-map",
  "[aout]",
  ...(subtitles
    ? [
        "-map",
        `${inputs.length + 1}:s`,
        "-c:s",
        "mov_text",
        "-metadata:s:s:0",
        "language=eng",
      ]
    : []),
  "-c:v",
  "copy",
  "-c:a",
  "aac",
  "-b:a",
  "160k",
  "-movflags",
  "+faststart",
  out,
);
execFileSync("ffmpeg", args, { stdio: "inherit" });
if (subtitles) hideSubtitles(out);
console.log(
  `${out}: ${inputs.length} narration segments over ${duration.toFixed(1)} s`,
);

// ffmpeg's MP4 writer enables the first track of every kind, and players
// show an enabled subtitle track by default. Clear the "enabled" flag in
// the track header of each subtitle track, in place.
function hideSubtitles(file) {
  const b = fs.readFileSync(file);
  const boxes = (start, end) => {
    const out = [];
    for (let i = start; i + 8 <= end; ) {
      const size = b.readUInt32BE(i);
      if (size < 8) break;
      out.push({
        type: b.toString("ascii", i + 4, i + 8),
        start: i,
        end: i + size,
      });
      i += size;
    }
    return out;
  };
  const child = (box, type) =>
    boxes(box.start + 8, box.end).find((c) => c.type === type);
  const moov = boxes(0, b.length).find((x) => x.type === "moov");
  let hidden = 0;
  for (const trak of boxes(moov.start + 8, moov.end)) {
    if (trak.type !== "trak") continue;
    const hdlr = child(child(trak, "mdia"), "hdlr");
    const kind = b.toString("ascii", hdlr.start + 16, hdlr.start + 20);
    if (kind !== "sbtl" && kind !== "text") continue;
    const tkhd = child(trak, "tkhd");
    // version (1 byte), then 24 bits of flags; bit 0 is "enabled".
    b[tkhd.start + 11] &= ~1;
    hidden++;
  }
  if (!hidden) throw new Error(`no subtitle track in ${file}`);
  fs.writeFileSync(file, b);
}
