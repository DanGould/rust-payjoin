#!/usr/bin/env node
// Lay the narration over a recorded take.
//
//   node mux.mjs TAKE.mp4 MARKS.json VO_DIR OUT.mp4
//
// MARKS.json comes from record.mjs: when each segment starts in the take.
// Each `<id>.wav` in VO_DIR is placed at its segment's start. A segment
// with no file is left silent, and one that runs into the next is reported,
// since the take held only as long as the audio it was recorded with.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const [take, marksFile, voDir, out] = process.argv.slice(2);
if (!out) {
  console.error("usage: node mux.mjs TAKE.mp4 MARKS.json VO_DIR OUT.mp4");
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
console.log(
  `${out}: ${inputs.length} narration segments over ${duration.toFixed(1)} s`,
);
