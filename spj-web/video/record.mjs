#!/usr/bin/env node
// Record one take of the silent payjoin demo as a silent MP4, plus the time
// each narration segment starts in it.
//
//   node record.mjs OUT.mp4 MARKS.json [THUMBNAIL.png]
//
// Environment: WALLETS_URL (the spj-web page), CHROME (a Chromium binary),
// VO_DIR (narration audio, `<id>.wav`), NARRATION (the script, for segments
// with no audio yet), WORK (scratch directory), CDP_PORT.
//
// A headless Chromium plays the take: cards and the wallets. Its first frame
// is the title card, which is also saved as THUMBNAIL.png at 1280x720.
// A drawn cursor moves to each button before it is pressed. The page is
// captured at twice its CSS size, and a camera that follows the action is
// applied afterwards with ffmpeg's zoompan, so close ups stay sharp.
//
// The voiceover sets the pace. Each segment starts at a mark and the take
// holds until its audio has played. The wallets run held: after each step a
// wallet waits until this script releases it, so a step never goes by before
// the voice has said what it is. Swapping in a longer read only makes the
// take longer.

import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const HERE = import.meta.dirname;
const OUT = path.resolve(process.argv[2] ?? "take.mp4");
const MARKS = path.resolve(process.argv[3] ?? "marks.json");
const THUMBNAIL = process.argv[4] ? path.resolve(process.argv[4]) : null;
const WORK = path.resolve(process.env.WORK ?? path.join(HERE, ".work"));
const FRAMES = path.join(WORK, "frames");
const WALLETS = process.env.WALLETS_URL ?? "http://127.0.0.1:3000";
const CHROME = process.env.CHROME ?? "chromium";
const PORT = Number(process.env.CDP_PORT ?? 9333);
const VO_DIR = process.env.VO_DIR ?? "";
const NARRATION = process.env.NARRATION ?? "";
const W = 1280;
const H = 720;
const DPR = 2;
const FPS = 30;
const OUT_SIZE = "1920x1080";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Narration: how long each segment is

function wavSeconds(file) {
  const b = fs.readFileSync(file);
  if (b.toString("ascii", 0, 4) !== "RIFF") return null;
  let byteRate = 0;
  for (let i = 12; i + 8 <= b.length; ) {
    const id = b.toString("ascii", i, i + 4);
    const size = b.readUInt32LE(i + 4);
    if (id === "fmt ") byteRate = b.readUInt32LE(i + 16);
    if (id === "data" && byteRate) return size / byteRate;
    i += 8 + size + (size % 2);
  }
  return null;
}

const scriptText =
  NARRATION && fs.existsSync(NARRATION)
    ? fs.readFileSync(NARRATION, "utf8")
    : "";
/** A segment's words, lower case and without punctuation. */
function segWords(id) {
  const m = scriptText
    .split(/^## +/m)
    .find((block) => block.startsWith(`${id}\n`) || block.startsWith(`${id} `));
  if (!m) return [];
  return m
    .split("\n")
    .slice(1)
    .join(" ")
    .toLowerCase()
    .split(/\s+/)
    .map((w) => w.replace(/[^a-z0-9'-]/g, ""))
    .filter(Boolean);
}
const words = (id) => segWords(id).length;

/**
 * How far into segment `id` the voice reaches `phrase`, as a fraction,
 * counting words. A read keeps roughly even pace within a segment, so this
 * holds for any voice.
 */
function phraseAt(id, phrase) {
  const all = segWords(id);
  const want = phrase.toLowerCase().split(/\s+/);
  for (let i = 0; i + want.length <= all.length; i++)
    if (want.every((w, j) => all[i + j] === w)) return i / all.length;
  throw new Error(`"${phrase}" is not in segment ${id}`);
}

/** A segment's length: its audio file's, or a reading-speed guess. */
function duration(id) {
  const file = VO_DIR && path.join(VO_DIR, `${id}.wav`);
  if (file && fs.existsSync(file)) {
    const s = wavSeconds(file);
    if (s) return s;
  }
  const guess = words(id) / 2.5;
  console.warn(`no audio for ${id}; holding ${guess.toFixed(1)} s`);
  return guess;
}

// ---------------------------------------------------------------------------
// Chromium and the DevTools protocol

fs.rmSync(WORK, { recursive: true, force: true });
fs.mkdirSync(FRAMES, { recursive: true });

const chrome = spawn(
  CHROME,
  [
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--no-proxy-server",
    "--remote-debugging-address=127.0.0.1",
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${path.join(WORK, "profile")}`,
    `--window-size=${W},${H}`,
    // The screencast ignores an emulated device scale factor; only this makes
    // its frames twice the page's CSS size.
    `--force-device-scale-factor=${DPR}`,
    "--hide-scrollbars",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    // Cards are local files that load the page's fonts.
    "--allow-file-access-from-files",
    "about:blank",
  ],
  { stdio: "ignore" },
);
process.on("exit", () => chrome.kill());

async function pageSocketUrl() {
  for (let i = 0; i < 200; i++) {
    try {
      const targets = await (
        await fetch(`http://127.0.0.1:${PORT}/json/list`)
      ).json();
      const page = targets.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      /* not up yet */
    }
    await sleep(100);
  }
  throw new Error("Chromium did not start");
}

class Cdp {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.id = 0;
    this.pending = new Map();
    this.handlers = new Map();
    this.ws.onmessage = (msg) => {
      const m = JSON.parse(msg.data);
      if (m.id && this.pending.has(m.id)) {
        const { resolve, reject } = this.pending.get(m.id);
        this.pending.delete(m.id);
        m.error
          ? reject(new Error(`${m.error.message} ${m.error.data ?? ""}`))
          : resolve(m.result);
      } else if (m.method) {
        (this.handlers.get(m.method) ?? []).forEach((h) => h(m.params));
      }
    };
  }
  open() {
    return new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) =>
      this.pending.set(id, { resolve, reject }),
    );
  }
  on(method, handler) {
    this.handlers.set(method, [...(this.handlers.get(method) ?? []), handler]);
  }
  once(method) {
    return new Promise((resolve) => {
      const h = (p) => {
        this.handlers.set(
          method,
          this.handlers.get(method).filter((x) => x !== h),
        );
        resolve(p);
      };
      this.on(method, h);
    });
  }
}

const cdp = new Cdp(await pageSocketUrl());
await cdp.open();
await cdp.send("Page.enable");
await cdp.send("Runtime.enable");
await cdp.send("Emulation.setDeviceMetricsOverride", {
  width: W,
  height: H,
  deviceScaleFactor: DPR,
  mobile: false,
});

async function evaluate(expression) {
  const { result, exceptionDetails } = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (exceptionDetails)
    throw new Error(
      exceptionDetails.exception?.description ?? exceptionDetails.text,
    );
  return result.value;
}

async function waitFor(expression, timeout = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (await evaluate(expression).catch(() => false)) return;
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${expression}`);
}

// ---------------------------------------------------------------------------
// Frames
//
// The screencast sends a frame whenever the page repaints; a tiny element
// that never stops animating keeps it repainting. Frames are timed by when
// they arrive. While a page loads, frames are dropped and the gap is cut out.

const frames = [];
let recording = false;
let skipped = 0;
let lastRaw = null;
let cutPending = false;
// Frames left to record before pausing on its own; for a single still.
let budget = Infinity;

cdp.on("Page.screencastFrame", ({ data, sessionId }) => {
  cdp.send("Page.screencastFrameAck", { sessionId }).catch(() => {});
  const t = Date.now() / 1000;
  if (!recording) return;
  if (cutPending && lastRaw !== null) {
    skipped += t - lastRaw - 1 / FPS;
    cutPending = false;
  }
  lastRaw = t;
  const file = path.join(
    FRAMES,
    `${String(frames.length).padStart(6, "0")}.jpg`,
  );
  fs.writeFileSync(file, Buffer.from(data, "base64"));
  frames.push({ file, t: t - skipped });
  if (--budget === 0) {
    budget = Infinity;
    pause();
  }
});

function pause() {
  recording = false;
  cutPending = true;
}
function resume() {
  recording = true;
}
const takeTime = () => Date.now() / 1000 - skipped;

// ---------------------------------------------------------------------------
// Narration marks and fast-forward

const marks = [];
const started = {};

/** Start a narration segment now. */
function seg(id) {
  started[id] = takeTime();
  marks.push({ id, t: started[id], d: duration(id) });
  console.log(`seg ${id} (${marks.at(-1).d.toFixed(1)} s)`);
}

/** Wait until segment `id`'s audio has played, plus a breath. */
async function hold(id, breath = 0.6) {
  const end = started[id] + duration(id) + breath;
  const wait = end - takeTime();
  if (wait > 0) await sleep(wait * 1000);
}

/** Wait until the voice reaches `phrase` in segment `id`. */
async function untilPhrase(id, phrase) {
  const wait = started[id] + duration(id) * phraseAt(id, phrase) - takeTime();
  if (wait > 0) await sleep(wait * 1000);
}

// Stretches of the take played faster in the video: [start, end, factor].
const fast = [];
function fastForward(factor) {
  fast.push([takeTime(), Infinity, factor]);
}
function normalSpeed() {
  fast.at(-1)[1] = takeTime();
}
/** Take time to video time. */
function warp(t) {
  let out = t;
  for (const [a, b, k] of fast)
    out -= Math.max(0, Math.min(t, b) - a) * (1 - 1 / k);
  return out;
}

// ---------------------------------------------------------------------------
// The wallets' pace

async function post(pathname, body = {}) {
  const res = await fetch(`${WALLETS}${pathname}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${pathname}: ${await res.text()}`);
  return res.json();
}
const release = () => post("/api/release", {});
const stage = (body) => post("/api/stage", body);
const pace = (body) => post("/api/pace", body);

const seen = (kind) => `window.__seen.has(${JSON.stringify(kind)})`;
const count = (kind, n) =>
  `(window.__count[${JSON.stringify(kind)}] ?? 0) >= ${n}`;

/**
 * Let the wallets run until the `n`th `kind` event of the take, then wait
 * for the page to have played it. Counts are from the start of the take,
 * the same on the server and the page.
 */
async function next(kind, n) {
  await post("/api/release", { until: kind, n });
  await waitFor(count(kind, n), 120000);
}

// ---------------------------------------------------------------------------
// The camera
//
// A keyframe says where the camera looks, in CSS pixels, how close, and how
// long the move takes. ffmpeg interpolates between them with an ease. It
// eases the view's centre and half width, not the zoom, so each edge of the
// view moves steadily one way: anything inside the view at both ends of a
// move stays inside it all the way through.

const camera = [{ t: -Infinity, z: 1, hw: W / 2, cx: W / 2, cy: H / 2, d: 0 }];
let view = { left: 0, top: 0, right: W, bottom: H };
let zoom = 1;

function look(cx, cy, z, d) {
  z = Math.min(Math.max(z, 1), 2.6);
  const hw = W / z / 2;
  const hh = H / z / 2;
  cx = Math.min(Math.max(cx, hw), W - hw);
  cy = Math.min(Math.max(cy, hh), H - hh);
  camera.push({ t: takeTime(), z, hw, cx, cy, d });
  zoom = z;
  view = { left: cx - hw, top: cy - hh, right: cx + hw, bottom: cy + hh };
  return evaluate(
    `document.documentElement.style.setProperty('--rec-zoom', ${z})`,
  ).catch(() => {});
}

// With `cy`, only the width has to fit: the camera looks at that height
// and may cut the top and bottom, so a phone beside the box stays out of
// the frame instead of showing half its screen.
//
// Nothing on the stage (a device, the transaction, the URI, the mailbox or
// network node) is ever cut by the left or right edge of the frame. The view
// slides off one beside what it frames if that still shows all of it, and
// otherwise widens to take the cut one in.
const WHOLE = ".stage .phone, #tx .card, #uri .uri-card, #lane .node";
async function frame(
  rect,
  { pad = 24, maxZoom = 2.2, d = 1.1, cy = null } = {},
) {
  const fit = (r) => {
    const fitW = W / (r.width + 2 * pad);
    const z = cy === null ? Math.min(fitW, H / (r.height + 2 * pad)) : fitW;
    return Math.min(Math.max(z, 1), maxZoom);
  };
  const whole = await evaluate(
    `[...document.querySelectorAll(${JSON.stringify(WHOLE)})].map((e) => { const r = e.getBoundingClientRect(); return { left: r.left, right: r.right }; })`,
  );
  let cx = null;
  for (let tries = 0; ; tries++) {
    // The view's edges, placed as look() places them.
    const hw = W / fit(rect) / 2;
    const centre = cx ?? rect.left + rect.width / 2;
    cx = Math.min(Math.max(centre, hw), W - hw);
    const cut = whole.find(
      (e) =>
        e.left < cx + hw &&
        e.right > cx - hw &&
        (e.left < cx - hw - 0.5 || e.right > cx + hw + 0.5),
    );
    if (!cut) break;
    if (tries > 12) return wide(d);
    const right = rect.left + rect.width;
    const slid =
      cut.left >= right
        ? cut.left - 1 - hw
        : cut.right <= rect.left
          ? cut.right + 1 + hw
          : null;
    if (
      slid !== null &&
      slid - hw >= 0 &&
      slid + hw <= W &&
      slid - hw <= rect.left &&
      slid + hw >= right
    ) {
      cx = slid;
      continue;
    }
    const left = Math.min(rect.left, cut.left);
    rect = { ...rect, left, width: Math.max(right, cut.right) - left };
    cx = null;
  }
  return look(cx, cy ?? rect.top + rect.height / 2, fit(rect), d);
}

const wide = (d = 1.1) => look(W / 2, H / 2, 1, d);

async function box(...expressions) {
  const r = await evaluate(`(() => {
    const els = [${expressions.join(",")}].flat().filter(Boolean);
    if (!els.length) return null;
    const rs = els.map((e) => e.getBoundingClientRect());
    const left = Math.min(...rs.map((r) => r.left)), top = Math.min(...rs.map((r) => r.top));
    const right = Math.max(...rs.map((r) => r.right)), bottom = Math.max(...rs.map((r) => r.bottom));
    return { left, top, width: right - left, height: bottom - top };
  })()`);
  if (!r) throw new Error(`nothing to frame for ${expressions.join(", ")}`);
  return r;
}

const $ = (selector) => `document.querySelector(${JSON.stringify(selector)})`;
const PAYER = $("#payer-party .phone");
const BOB = $('[data-who="bob"] .phone');
const LANE = $("#lane");

// ---------------------------------------------------------------------------
// The cursor, spotlight, captions and fades, put into every page the take
// visits. Sizes are divided by the camera's zoom so they look the same
// however close the camera is.

const STAGEHANDS = `(() => {
  if (document.getElementById('rec-cursor')) return true;
  const style = document.createElement('style');
  style.textContent = \`
    :root { --rec-zoom: 1; }
    #rec-cursor { position: fixed; left: 0; top: 0; width: 30px; height: 30px; z-index: 2147483647; pointer-events: none;
      transform: translate(${W * 0.5}px, ${H * 0.62}px); transition: transform .75s cubic-bezier(.45,.05,.25,1), opacity .3s; }
    #rec-cursor svg { filter: drop-shadow(0 2px 3px rgba(0,0,0,.35)); transition: transform .12s; transform-origin: 4px 3px;
      transform: scale(calc(1.15 / var(--rec-zoom))); }
    #rec-cursor.press svg { transform: scale(calc(.95 / var(--rec-zoom))); }
    .rec-ripple { position: fixed; z-index: 2147483646; pointer-events: none; width: 44px; height: 44px; margin: -22px 0 0 -22px;
      border-radius: 50%; border: 3px solid rgba(233,168,0,.9); animation: rec-ripple .55s ease-out forwards; }
    @keyframes rec-ripple { from { transform: scale(calc(.3 / var(--rec-zoom))); opacity: 1; } to { transform: scale(calc(1.3 / var(--rec-zoom))); opacity: 0; } }
    #rec-ticker { position: fixed; right: 0; bottom: 0; width: 2px; height: 2px; pointer-events: none; animation: rec-tick 1s linear infinite; }
    @keyframes rec-tick { from { background-color: rgba(128, 128, 128, .02); } to { background-color: rgba(128, 128, 128, .04); } }
    #rec-spot { position: fixed; z-index: 2147483640; pointer-events: none; opacity: 0;
      border: 3px solid #e9a800; border-radius: 12px;
      box-shadow: 0 0 0 200vmax rgba(4, 7, 14, .55), 0 0 26px 4px rgba(233, 168, 0, .45);
      transition: left .6s cubic-bezier(.45,.05,.25,1), top .6s cubic-bezier(.45,.05,.25,1), width .6s cubic-bezier(.45,.05,.25,1), height .6s cubic-bezier(.45,.05,.25,1), opacity .45s; }
    #rec-spot.on { opacity: 1; }
    #rec-caption { position: fixed; left: 0; top: 0; z-index: 2147483641; pointer-events: none; transform-origin: 0 0; }
    #rec-caption .card, #rec-say .card { max-width: 640px; padding: 12px 20px 12px 18px; border-radius: 12px; text-align: left;
      background: #ffffff; color: #14171f; border-left: 7px solid #e9a800; box-shadow: 0 22px 44px -14px rgba(0, 0, 0, .6), 0 0 0 1px rgba(20, 23, 31, .08);
      font: 600 26px/1.25 'Schibsted Grotesk', 'Helvetica Neue', sans-serif; letter-spacing: -.01em;
      opacity: 0; transform: translateY(10px); transition: opacity .35s, transform .35s; }
    #rec-caption.on .card, #rec-say.on .card { opacity: 1; transform: none; }
    #rec-caption small, #rec-say small { display: block; margin-top: 3px; font-weight: 400; font-size: 20px; color: #3a404d; }
    #rec-caption { transition: left .6s cubic-bezier(.45,.05,.25,1), top .6s cubic-bezier(.45,.05,.25,1); }
    #rec-say { position: fixed; left: 0; top: 0; z-index: 2147483642; pointer-events: none; transform-origin: 0 0; }
    #rec-fade { position: fixed; inset: 0; z-index: 2147483645; pointer-events: none; background: #05080f; opacity: 0; transition: opacity .6s ease; }
    #rec-fade.on { opacity: 1; }
    #rec-fade.now { transition: none; }
    #rec-ff { position: fixed; z-index: 2147483643; right: 24px; top: 14px; pointer-events: none; opacity: 0; transition: opacity .3s;
      background: #14171f; color: #fff; font: 700 22px/1 'Schibsted Grotesk', sans-serif; padding: 10px 16px; border-radius: 999px; transform-origin: 100% 0; }
    #rec-ff.on { opacity: 1; }
  \`;
  document.head.appendChild(style);
  const add = (id, html = '') => { const el = document.createElement('div'); el.id = id; el.innerHTML = html; document.body.appendChild(el); return el; };
  add('rec-cursor', '<svg width="30" height="30" viewBox="0 0 24 24"><path d="M4 2.5v17.2l4.6-4.4 3 6.7 3.1-1.4-3-6.6 6.4-.4z" fill="#fff" stroke="#14171f" stroke-width="1.6" stroke-linejoin="round"/></svg>');
  add('rec-ticker');
  const spot = add('rec-spot');
  const caption = add('rec-caption', '<div class="card"></div>');
  add('rec-fade');
  const say = add('rec-say', '<div class="card"></div>');
  add('rec-ff', '▶▶ fast forward');
  // A caption at the foot (or top) of what the camera shows, scaled by its
  // zoom so it comes out the same size in the video.
  window.__say = (text, note, view, zoom, where) => {
    const card = say.firstChild;
    card.innerHTML = text + (note ? '<small>' + note + '</small>' : '');
    const s = 1 / zoom;
    const w = card.offsetWidth * s, h = card.offsetHeight * s;
    const left = (view.left + view.right) / 2 - w / 2;
    const top = where === 'top' ? view.top + 24 * s : view.bottom - h - 24 * s;
    Object.assign(say.style, { left: left + 'px', top: top + 'px', transform: 'scale(' + s + ')' });
    say.offsetHeight;
    say.classList.add('on');
  };
  window.__hush = () => say.classList.remove('on');
  // Ring a part of the page, dim the rest, and caption it beside the ring,
  // inside the camera's view.
  window.__spot = (r, text, note, view, zoom, above) => {
    const pad = 8 / zoom;
    const box = { left: r.left - pad, top: r.top - pad, width: r.width + 2 * pad, height: r.height + 2 * pad };
    const fresh = !spot.classList.contains('on');
    if (fresh) { spot.style.transition = 'none'; caption.style.transition = 'none'; }
    spot.style.borderWidth = (3 / zoom) + 'px';
    spot.style.borderRadius = (12 / zoom) + 'px';
    Object.assign(spot.style, { left: box.left + 'px', top: box.top + 'px', width: box.width + 'px', height: box.height + 'px' });
    const card = caption.firstChild;
    card.innerHTML = text + (note ? '<small>' + note + '</small>' : '');
    const s = 1 / zoom;
    const cw = card.offsetWidth * s, ch = card.offsetHeight * s, gap = 14 * s, m = 10 * s;
    // Below the ring, or above it when there's no room; with an anchor,
    // above the anchor, so the caption covers nothing next to the ring.
    const below = box.top + box.height + gap;
    let top = below + ch < view.bottom - m ? below : Math.max(view.top + m, box.top - ch - gap);
    if (above) top = Math.max(view.top + m, above.top - ch - gap);
    const left = Math.min(Math.max(view.left + m, box.left), view.right - cw - m);
    Object.assign(caption.style, { left: left + 'px', top: top + 'px', transform: 'scale(' + s + ')' });
    caption.firstChild.style.display = text ? '' : 'none';
    if (fresh) { spot.offsetHeight; spot.style.transition = ''; caption.style.transition = ''; }
    spot.classList.add('on');
    caption.classList.add('on');
  };
  window.__unspot = () => { spot.classList.remove('on'); caption.classList.remove('on'); };
  window.__ff = (on, zoom) => { const f = document.getElementById('rec-ff'); f.style.transform = 'scale(' + (1 / zoom) + ')'; f.classList.toggle('on', on); };
  return true;
})()`;

async function goto(url, ready, prepare = null) {
  pause();
  const loaded = cdp.once("Page.loadEventFired");
  await cdp.send("Page.navigate", { url });
  await loaded;
  await waitFor(ready, 90000);
  await evaluate(STAGEHANDS);
  await evaluate(
    `document.documentElement.style.setProperty('--rec-zoom', ${zoom})`,
  );
  if (prepare) await evaluate(prepare);
  await sleep(400);
  resume();
}

const coverNow = `(() => { const f = document.getElementById('rec-fade'); f.classList.add('now', 'on'); f.offsetHeight; f.classList.remove('now'); })()`;

async function pointAt(expression) {
  const r = await box(expression);
  await evaluate(
    `document.getElementById('rec-cursor').style.transform = 'translate(${r.left + Math.min(r.width / 2, 60) - 4}px, ${r.top + r.height / 2 - 3}px)'`,
  );
}

// Move the drawn cursor onto an element, press, then click it for real
// (unless `follow` is false: a link the take opens itself).
async function click(selector, { follow = true } = {}) {
  await waitFor(`${$(selector)} && !${$(selector)}.disabled`);
  const r = await box($(selector));
  const x = r.left + r.width / 2;
  const y = r.top + r.height / 2;
  await evaluate(
    `document.getElementById('rec-cursor').style.transform = 'translate(${x - 4}px, ${y - 3}px)'`,
  );
  await sleep(850);
  await evaluate(`(() => {
    const c = document.getElementById('rec-cursor');
    c.classList.add('press');
    const ripple = document.createElement('div');
    ripple.className = 'rec-ripple';
    ripple.style.left = '${x}px'; ripple.style.top = '${y}px';
    document.body.appendChild(ripple);
    setTimeout(() => ripple.remove(), 600);
    setTimeout(() => c.classList.remove('press'), 140);
  })()`);
  await sleep(160);
  if (follow) await evaluate(`${$(selector)}.click()`);
}

const park = () =>
  evaluate(
    `document.getElementById('rec-cursor').style.transform = 'translate(${W * 0.5}px, ${H + 60}px)'`,
  );
// A caption stays up at least this long, however soon the take moves on.
const DWELL = 2500;
let spotAt = 0;
const spot = async (expression, text, note = "", above = null) => {
  spotAt = Date.now();
  const anchor = above ? await box(above) : null;
  await evaluate(
    `window.__spot(${JSON.stringify(await box(expression))}, ${JSON.stringify(text)}, ${JSON.stringify(note)}, ${JSON.stringify(view)}, ${zoom}, ${JSON.stringify(anchor)})`,
  );
};
const CARD = $("#tx .card");
const unspot = async () => {
  await sleep(Math.max(0, spotAt + DWELL - Date.now()));
  await evaluate("window.__unspot()");
  await sleep(450);
};
const say = (text, note = "", where = "bottom") =>
  evaluate(
    `window.__say(${JSON.stringify(text)}, ${JSON.stringify(note)}, ${JSON.stringify(view)}, ${zoom}, ${JSON.stringify(where)})`,
  );
const hush = async () => {
  await evaluate("window.__hush()");
  await sleep(350);
};
const fadeOut = async () => {
  await evaluate(`document.getElementById('rec-fade').classList.add('on')`);
  await sleep(700);
};
const fadeIn = async () => {
  await evaluate(`document.getElementById('rec-fade').classList.remove('on')`);
  await sleep(700);
};
const cursor = (on) =>
  evaluate(
    `document.getElementById('rec-cursor').style.opacity = ${on ? 1 : 0}`,
  );

const card = (name) => `file://${path.join(HERE, "cards", name)}`;
const cardReady = `document.fonts.status === 'loaded'`;

// A card line marked `data-at="phrase"` rises when the voice reaches that
// phrase of the segment, whatever the read's length.
async function timeCard(id) {
  const lines = await evaluate(
    `[...document.querySelectorAll('[data-at]')].map((e) => e.dataset.at)`,
  );
  const at = lines.map((phrase) =>
    Math.max(0, duration(id) * phraseAt(id, phrase) - 0.2),
  );
  await evaluate(
    `[...document.querySelectorAll('[data-at]')].forEach((e, i) => e.style.setProperty('--i', ${JSON.stringify(at)}[i]))`,
  );
}

/** Show a card for a narration segment, at least `min` seconds. */
async function showCard(name, id, min = 6) {
  await fadeOut();
  look(W / 2, H / 2, 1, 0);
  await goto(
    card(name),
    cardReady,
    `${coverNow}; document.getElementById('rec-cursor').style.opacity = 0`,
  );
  await timeCard(id);
  await fadeIn();
  const t0 = takeTime();
  seg(id);
  await evaluate(`document.body.classList.add('go')`);
  await hold(id);
  const left = min - (takeTime() - t0);
  if (left > 0) await sleep(left * 1000);
}

const walletsReady = `window.__ready === true && document.fonts.status === 'loaded'`;
async function toWallets() {
  await fadeOut();
  look(W / 2, H / 2, 1, 0);
  await goto(WALLETS, walletsReady, coverNow);
  await fadeIn();
}

// ---------------------------------------------------------------------------
// The take

await cdp.send("Page.startScreencast", {
  format: "jpeg",
  quality: 88,
  maxWidth: W * DPR,
  maxHeight: H * DPR,
  everyNthFrame: 1,
});
await pace({ held: true, ms: 700 });

// The title card: one frame, so it is what a player shows before playing.
budget = 1;
await goto(
  card("title.html"),
  cardReady,
  `document.getElementById('rec-cursor').style.opacity = 0`,
);
while (recording) await sleep(20);
if (THUMBNAIL) {
  const { data } = await cdp.send("Page.captureScreenshot", {
    format: "png",
    clip: { x: 0, y: 0, width: W, height: H, scale: 1 / DPR },
  });
  fs.writeFileSync(THUMBNAIL, Buffer.from(data, "base64"));
}

// 0. What the video shows.
await goto(
  card("intro.html"),
  cardReady,
  `document.getElementById('rec-cursor').style.opacity = 0`,
);
await timeCard("intro");
seg("intro");
await evaluate(`document.body.classList.add('go')`);
await hold("intro");
await sleep(1200);

// 1. The problem, and the two ways the video shows.
await showCard("problem.html", "problem", 9);
await showCard("overview.html", "overview", 6);

// 2. A one-time URI, paid by a wallet without silent payments.
await showCard("onetime.html", "one-time", 4);
await stage({ payer: "carol", amount: 40000, clear: true });
await toWallets();
seg("uri");
await frame(await box(LANE, BOB), { pad: 8, cy: 310 });
await click('#bob [data-act="receive"]');
await waitFor(`${$("#uri .part.sp")}`);
await sleep(500);
await park();
await spot($("#uri .part.addr"), "An ordinary address");
await sleep(1500);
await spot(
  $("#uri .part.sp"),
  "Bob's silent payment address",
  "Labelled for this URI",
);
await sleep(1600);
await spot($("#uri .part.pj"), "A payjoin mailbox");
await hold("uri");
await unspot();

seg("carol");
await frame(await box(PAYER), { pad: 20 });
await click('#payer [data-act="scan"]');
await waitFor(`${$('#payer [data-act="send"]')}`);
await sleep(300);
await spot(
  $("#payer .sees"),
  "Carol's wallet skips sp=",
  "It pays the address, as a payjoin",
);
await sleep(1700);
await unspot();
await click('#payer [data-act="send"]');
// Carol's payjoin is the ordinary kind; its steps go by quickly.
await pace({ held: true, ms: 400 });
await park();
await wide(1.3);
await next("carol.original_sent", 1);
await next("bob.coin", 1);
await spot($('#tx .row.bob[data-key^="in-"]'), "Bob adds a coin", "", CARD);
await sleep(1600);
await unspot();
await next("carol.confirmed", 1);
await release();
await waitFor(count("bob.received", 1));
await hold("carol");
await sleep(500);

// 3. A one-time URI, paid by a silent payment wallet.
await stage({ payer: "alice", amount: 50000, clear: true });
await sleep(400);
seg("alice-scan");
await pace({ held: true, ms: 700 });
await frame(await box(BOB), { pad: 20 });
await click('#bob [data-act="receive"]');
await waitFor(`${$("#bob .qr svg")}`);
await sleep(600);
await frame(await box(PAYER), { pad: 20 });
await click('#payer [data-act="scan"]');
await waitFor(`${$('#payer [data-act="send"]')}`);
await sleep(300);
await spot(
  $("#payer .sees"),
  "Alice's wallet reads sp=",
  "A silent payment, with payjoin",
);
await hold("alice-scan");
await unspot();

seg("alice-send");
await click('#payer [data-act="send"]');
await park();
await frame(await box(PAYER, LANE), { pad: 8, d: 1.3, cy: 310 });
await next("alice.original_sent", 1);
await spot(
  $('#tx .row.bob[data-key^="out-"]'),
  "Bob's output, worked out by Alice",
  "From her inputs and his silent payment address",
  CARD,
);
await waitFor(count("bob.original", 2));
await hold("alice-send");
await unspot();

seg("bob-adds");
await frame(await box(LANE, BOB), { pad: 8, d: 1.3, cy: 310 });
await next("bob.found", 2);
await say("Bob finds it by scanning", "", "top");
await sleep(1800);
await hush();
await next("bob.coin", 2);
await spot(
  $('#tx .row.bob[data-key^="in-"]'),
  "Bob's coin, with a proof",
  "So Alice can check his math before she signs",
  CARD,
);
await sleep(2600);
await spot(
  $('#tx .row.bob[data-key^="out-"]'),
  "His output, worked out again",
  "Over all the inputs, his coin included",
  CARD,
);
await hold("bob-adds");
await unspot();

seg("alice-checks");
await frame(await box(PAYER, LANE), { pad: 8, d: 1.3, cy: 310 });
await next("alice.proposal", 1);
await next("alice.checked", 1);
await spot($('#tx .row.bob[data-key^="in-"]'), "Proof checked", "", CARD);
await sleep(2000);
await spot(
  $('#tx .row.bob[data-key^="out-"]'),
  "Alice gets the same key",
  "And it pays Bob at least 50,000 sats",
  CARD,
);
await hold("alice-checks");
await unspot();

seg("confirmed");
await wide(1.3);
await next("alice.broadcast", 1);
await next("alice.confirmed", 1);
await release();
await waitFor(count("bob.received", 2));
await spot($("#bob .list li"), "Found by scanning");
await untilPhrase("confirmed", "and if bob");
await spot(
  $("#bob .list li"),
  "Found by scanning",
  "A wallet restored from Bob's backup words finds it the same way",
);
await hold("confirmed");
await unspot();

seg("contact-note");
// A URI carries no name: Alice types one, a key at a time.
await frame(await box(PAYER), {
  pad: 16,
  cy: (await box($("#payer .save-contact"))).top + 40,
});
await click("#contact-name", { follow: false });
await evaluate(`${$("#contact-name")}.focus()`);
await say("A URI carries no name, so Alice types one", "", "top");
await sleep(300);
for (const key of "Bob") {
  await cdp.send("Input.insertText", { text: key });
  await sleep(220);
}
await sleep(400);
await click('#payer [data-act="save-contact"]');
await waitFor(count("alice.contact_saved", 1));
await hush();
await park();
await sleep(600);
await spot($("#payer .contact .note"), "");
await untilPhrase("contact-note", "she can scan");
await spot(
  $("#payer .note-scan"),
  "Scan Bob's contact URI",
  "For reusable payjoin",
  $("#payer .contact"),
);
await hold("contact-note");
await unspot();

// 4. A contact URI, for someone Bob transacts with again and again.
await showCard("contact.html", "contact", 8);

// 5. Bob withdraws from his exchange, which has his contact URI.
await stage({
  payer: "exchange",
  amount: 100000,
  reply_by: 60,
  payout: "withdrawal",
  clear: true,
});
await toWallets();
seg("exchange-contact");
await frame(await box(LANE, BOB), { pad: 8, cy: 310 });
await click('#bob [data-act="share-contact"]');
await waitFor(`${$("#uri .part.sp")}`);
await park();
await sleep(400);
await spot(
  $("#uri .part.addr"),
  "No address",
  "Only the silent payment address and a mailbox",
);
await sleep(1600);
await spot(
  $("#uri .part.sp"),
  "One label for the exchange",
  "The same on every transfer from it",
);
await sleep(1800);
await unspot();
await frame(await box(PAYER), { pad: 20 });
await click('#payer [data-act="scan"]');
await waitFor(`${$("#payer .contact")}`);
await park();
await spot($("#payer .contact"), "Saved once");
await hold("exchange-contact");
await unspot();
await wide(1.1);
await click('#bob [data-act="bob-home"]');
await park();
// Bob's home screen slides in; measure it once it is still.
await sleep(900);

seg("withdraw");
const withdraw = await box($('#bob [data-act="withdraw"]'));
await frame(await box(BOB), { pad: 20, cy: withdraw.top - 20, d: 1.1 });
await spot($('#bob [data-act="withdraw"]'), "Bob withdraws from his exchange");
await sleep(1600);
await unspot();
await click('#bob [data-act="withdraw"]');
// The transaction was shown in full for Alice; this one moves faster.
await pace({ held: true, ms: 400 });
await park();
await wide(1.2);
await say(
  "Bob's wallet is open, so the withdrawal is a Silent Payjoin",
  "",
  "top",
);
await next("exchange.original_sent", 1);
await next("bob.coin", 3);
await next("exchange.confirmed", 1);
await release();
await waitFor(count("bob.received", 3));
await hold("withdraw");

// Two more withdrawals, faster.
await pace({ held: false, ms: 250 });
fastForward(4);
await evaluate(`window.__ff(true, ${zoom})`);
for (const n of [2, 3]) {
  await click('#bob [data-act="withdraw"]');
  await park();
  await waitFor(count("exchange.confirmed", n), 120000);
  await waitFor(count("bob.received", n + 2), 120000);
  await sleep(600);
}
await evaluate(`window.__ff(false, ${zoom})`);
normalSpeed();
await pace({ held: true, ms: 700 });
seg("withdraw-more");
await frame(await box(PAYER), { pad: 16 });
await spot(
  $("#payer .list"),
  "Three Silent Payjoins",
  "All found by Bob's scan",
);
await hold("withdraw-more");
await unspot();

// 6. What can go wrong: a stolen mailbox key, and Bob offline when the
// exchange's schedule pays him.
await stage({ reply_by: 4, payout: "scheduled", clear: true });
await pace({ held: false, ms: 900 });
await wide(1.2);
seg("offline");
await say("Two things can go wrong", "", "top");
await untilPhrase("offline", "if someone steals");
await hush();
await say(
  "A stolen mailbox key can't redirect the money",
  "The payer only signs for the output it worked out",
  "top",
);
await untilPhrase("offline", "and if bob is offline");
await hush();
await say(
  "Bob is offline",
  "A scheduled payout he didn't start doesn't wait for him",
  "top",
);
// The phone goes to sleep on "like now".
await untilPhrase("offline", "like now");
await post("/api/bob/awake", { awake: false });
await sleep(1200);
await spot($("#payer .scheduled"), "Due now");
await sleep(1400);
await unspot();
await hush();
// The exchange's schedule starts it, not a click.
const scheduled = post("/api/exchange/pay-contact", {
  amount: 100000,
  reply_by: 4,
});
await waitFor(seen("exchange.fallback"), 60000);
await spot(
  $("#tx .card"),
  "No answer from Bob",
  "The transaction goes out as it is, a plain silent payment",
  CARD,
);
await waitFor(count("exchange.confirmed", 4), 60000);
await scheduled;
await hold("offline");
await unspot();
// Bob's phone reads the mailbox as he wakes: close in on its steps.
const bobPhone = await box(BOB);
await frame(bobPhone, { pad: 20, cy: bobPhone.top + 190, d: 1.2 });
await sleep(1200);
seg("offline-wake");
await post("/api/bob/awake", { awake: true });
await waitFor(count("bob.received", 6), 60000);
await sleep(600);
await spot(
  $("#bob .steps"),
  "Read from the mailbox, found by scanning",
  "A plain silent payment",
);
await hold("offline-wake");
await unspot();

// 7. What the video showed, and why not one open mailbox.
await showCard("recap.html", "recap", 10);

// 8. The end card.
await showCard("endcard.html", "end", 6);
await sleep(800);

const takeEnd = takeTime();
await cdp.send("Page.stopScreencast");
recording = false;

// ---------------------------------------------------------------------------
// Encode: frames at their real timing, the fast stretches sped up, then the
// camera.

if (frames.length < 2) throw new Error("no frames captured");
const t0 = warp(frames[0].t);
const at = (t) => warp(t) - t0;
const end = Math.max(at(takeEnd), at(frames.at(-1).t) + 1 / FPS);
const list =
  frames
    .map((f, i) => {
      const nextT = i + 1 < frames.length ? at(frames[i + 1].t) : end;
      return `file '${f.file}'\nduration ${Math.max(0.001, nextT - at(f.t)).toFixed(4)}`;
    })
    .join("\n") + `\nfile '${frames.at(-1).file}'\n`;
const listFile = path.join(WORK, "frames.txt");
fs.writeFileSync(listFile, list);

for (const key of camera) key.t = Math.max(0, at(key.t));

function jpegWidth(file) {
  const b = fs.readFileSync(file);
  for (let i = 2; i < b.length - 8; ) {
    const marker = b[i + 1];
    const length = b.readUInt16BE(i + 2);
    if (
      marker >= 0xc0 &&
      marker <= 0xcf &&
      ![0xc4, 0xc8, 0xcc].includes(marker)
    )
      return b.readUInt16BE(i + 7);
    i += 2 + length;
  }
  throw new Error(`no frame size in ${file}`);
}
const scale = jpegWidth(frames[0].file) / W;
if (scale !== DPR)
  console.warn(
    `frames are ${scale}x the page, not ${DPR}x; close ups will be softer`,
  );

function track(key) {
  let e = camera[0][key].toFixed(3);
  for (let i = 1; i < camera.length; i++) {
    const delta = camera[i][key] - camera[i - 1][key];
    if (Math.abs(delta) < 1e-4) continue;
    const s0 = camera[i].t.toFixed(3);
    if (camera[i].d <= 0) {
      e += `+(${delta.toFixed(4)})*gte(it,${s0})`;
    } else {
      const u = `clip((it-${s0})/${camera[i].d},0,1)`;
      e += `+(${delta.toFixed(4)})*${u}*${u}*(3-2*${u})`;
    }
  }
  return e;
}
const zoompan = [
  `zoompan=z='${W / 2}/(${track("hw")})'`,
  `x='clip((${track("cx")})*${scale}-iw/zoom/2,0,iw-iw/zoom)'`,
  `y='clip((${track("cy")})*${scale}-ih/zoom/2,0,ih-ih/zoom)'`,
  `d=1:s=${OUT_SIZE}:fps=${FPS}`,
].join(":");
const filterFile = path.join(WORK, "camera.filter");
fs.writeFileSync(filterFile, `fps=${FPS},${zoompan},format=yuv420p`);
fs.mkdirSync(path.dirname(OUT), { recursive: true });
execFileSync(
  "ffmpeg",
  [
    "-y",
    "-loglevel",
    "error",
    "-f",
    "concat",
    "-safe",
    "0",
    "-i",
    listFile,
    "-/vf",
    filterFile,
    "-c:v",
    "libx264",
    "-preset",
    "medium",
    "-crf",
    "18",
    "-movflags",
    "+faststart",
    OUT,
  ],
  { stdio: "inherit" },
);

const placed = marks.map((m) => ({
  id: m.id,
  t: Number(at(m.t).toFixed(3)),
  d: Number(m.d.toFixed(3)),
}));
fs.writeFileSync(
  MARKS,
  JSON.stringify({ duration: Number(end.toFixed(3)), marks: placed }, null, 1),
);
console.log(
  `${OUT}: ${end.toFixed(1)} s from ${frames.length} frames, ${camera.length} camera moves, ${placed.length} segments`,
);
chrome.kill();
fs.rmSync(FRAMES, { recursive: true, force: true });
process.exit(0);
