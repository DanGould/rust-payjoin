// Drive a headless Chromium over CDP to film a mempool transaction page: a
// full-page screenshot, then a sweep of viewport frames from the top of the
// page to the bottom. Bare node 22 (global WebSocket and fetch), no packages.
//
//   node capture.mjs <debugging port> <url> <out dir> [frames]
const [, , PORT, URL_, OUT, FRAMES = "48"] = process.argv;
const DEBUG = `http://127.0.0.1:${PORT}`;
const WIDTH = 1280;
const HEIGHT = 900;
const fs = await import("node:fs/promises");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function target() {
  for (let i = 0; i < 60; i++) {
    try {
      const list = await (await fetch(`${DEBUG}/json/list`)).json();
      const page = list.find((t) => t.type === "page");
      if (page) return page;
    } catch {
      // Chromium is not listening yet.
    }
    await sleep(500);
  }
  throw new Error("no debuggable page");
}

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.events = new Map();
    ws.addEventListener("message", (m) => {
      const msg = JSON.parse(m.data);
      if (msg.id !== undefined) {
        const entry = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error
          ? entry.reject(new Error(JSON.stringify(msg.error)))
          : entry.resolve(msg.result);
      } else {
        this.events.get(msg.method)?.forEach((f) => f(msg.params));
      }
    });
  }

  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) =>
      this.pending.set(id, { resolve, reject }),
    );
  }

  once(method) {
    return new Promise((resolve) => {
      const list = this.events.get(method) ?? [];
      list.push(resolve);
      this.events.set(method, list);
    });
  }

  async eval(expression) {
    const { result } = await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    return result.value;
  }
}

const page = await target();
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
const cdp = new Cdp(ws);

await cdp.send("Page.enable");
await cdp.send("Runtime.enable");
await cdp.send("Emulation.setDeviceMetricsOverride", {
  width: WIDTH,
  height: HEIGHT,
  deviceScaleFactor: 2,
  mobile: false,
});

const loaded = cdp.once("Page.loadEventFired");
await cdp.send("Page.navigate", { url: URL_ });
await loaded;

// The page renders from API calls after load. Wait until the transaction id
// is on the page, which also proves the backend found the transaction.
const txid = new URL(URL_).pathname.split("/").pop();
let found = false;
for (let i = 0; i < 60 && !found; i++) {
  await sleep(500);
  found = await cdp.eval(
    `document.body.innerText.includes(${JSON.stringify(txid.slice(0, 16))})`,
  );
}
if (!found) throw new Error(`the page never showed ${txid}`);
await sleep(2000);

// Inputs and outputs stay collapsed until Details is open, and that list is
// what the video is for.
const clicked = await cdp.eval(`(() => {
  const hit = [...document.querySelectorAll('button, a')]
    .find((el) => /details/i.test(el.textContent ?? ''));
  if (hit) { hit.click(); return hit.textContent.trim(); }
  return null;
})()`);
console.log("details toggle:", clicked);
await sleep(2000);

await fs.mkdir(`${OUT}/frames`, { recursive: true });
const shot = async (file, params = {}) => {
  const { data } = await cdp.send("Page.captureScreenshot", {
    format: "png",
    ...params,
  });
  await fs.writeFile(file, Buffer.from(data, "base64"));
};

const metrics = await cdp.send("Page.getLayoutMetrics");
const height = Math.ceil(metrics.cssContentSize.height);
await shot(`${OUT}/tx-full.png`, {
  captureBeyondViewport: true,
  clip: { x: 0, y: 0, width: WIDTH, height, scale: 1 },
});

// Sweep down to the bottom of the transaction, not the site footer.
const footerTop = await cdp.eval(`(() => {
  const footer = document.querySelector('app-global-footer, footer');
  return footer ? Math.floor(footer.getBoundingClientRect().top + window.scrollY) : null;
})()`);
const end = footerTop ? Math.min(height, footerTop + 40) : height;
const frames = Number(FRAMES);
const span = Math.max(0, end - HEIGHT);
for (let i = 0; i < frames; i++) {
  const y = Math.round((span * i) / Math.max(1, frames - 1));
  await cdp.eval(`window.scrollTo(0, ${y})`);
  await sleep(150);
  await shot(`${OUT}/frames/${String(i).padStart(3, "0")}.png`);
}
console.log(`captured ${frames} frames of a ${height}px page`);
ws.close();
